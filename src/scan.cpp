#include "scan.hpp"
#include "hash.hpp"

#include <algorithm>
#include <atomic>
#include <thread>
#include <mutex>
#include <filesystem>
#include <system_error>

#include <sys/stat.h>
#include <unistd.h>
#include <fnmatch.h>

namespace fs = std::filesystem;

namespace vigil {

bool path_excluded(const std::string& relpath,
                   const std::vector<std::string>& patterns) {
    if (patterns.empty() || relpath == ".") return false;
    for (const auto& pat : patterns) {
        if (pat.find('/') != std::string::npos) {
            // Path pattern: match the full path or any ancestor prefix so that
            // excluding "var/cache" also prunes everything beneath it.
            for (size_t i = 0; i <= relpath.size(); ++i) {
                if (i == relpath.size() || relpath[i] == '/') {
                    std::string prefix = relpath.substr(0, i);
                    if (!prefix.empty() &&
                        ::fnmatch(pat.c_str(), prefix.c_str(), FNM_PATHNAME) == 0)
                        return true;
                }
            }
        } else {
            // Bare pattern: match any single path component (basename of the
            // entry or of any ancestor directory).
            size_t start = 0;
            for (size_t i = 0; i <= relpath.size(); ++i) {
                if (i == relpath.size() || relpath[i] == '/') {
                    std::string comp = relpath.substr(start, i - start);
                    if (!comp.empty() && ::fnmatch(pat.c_str(), comp.c_str(), 0) == 0)
                        return true;
                    start = i + 1;
                }
            }
        }
    }
    return false;
}

const char* entry_type_name(EntryType t) {
    switch (t) {
        case EntryType::File:    return "file";
        case EntryType::Dir:     return "dir";
        case EntryType::Symlink: return "symlink";
        default:                 return "other";
    }
}

namespace {

// Fill the metadata fields of `r` from an lstat of `abs`. Returns false if the
// object vanished between enumeration and stat.
bool stat_into(const std::string& abs, Record& r) {
    struct stat st{};
    if (::lstat(abs.c_str(), &st) != 0) return false;
    r.mode  = (uint32_t)st.st_mode;
    r.uid   = (uint32_t)st.st_uid;
    r.gid   = (uint32_t)st.st_gid;
    r.size  = (uint64_t)st.st_size;
    r.mtime = (int64_t)st.st_mtime;
    if (S_ISREG(st.st_mode))      r.type = EntryType::File;
    else if (S_ISDIR(st.st_mode)) r.type = EntryType::Dir;
    else if (S_ISLNK(st.st_mode)) r.type = EntryType::Symlink;
    else                          r.type = EntryType::Other;
    return true;
}

} // namespace

bool make_record(const std::string& abs, const std::string& relpath, Record& out) {
    Record r;
    r.path = relpath;
    if (!stat_into(abs, r)) return false;
    if (r.type == EntryType::File) {
        try { r.hash = sha3_file(abs); }
        catch (const std::exception&) { r.hash.clear(); }
    } else if (r.type == EntryType::Symlink) {
        std::error_code ec;
        std::string target = fs::read_symlink(fs::path(abs), ec).string();
        if (ec) target.clear();
        r.hash = sha3(reinterpret_cast<const uint8_t*>(target.data()), target.size());
    }
    out = std::move(r);
    return true;
}

ScanResult scan_tree(const std::string& root, const ScanOptions& opt) {
    ScanResult res;

    std::error_code ec;
    fs::path canon = fs::weakly_canonical(fs::path(root), ec);
    if (ec || !fs::exists(canon)) throw Error("scan root does not exist: '" + root + "'");
    res.root = canon.string();
    res.excludes = opt.excludes;

    dev_t root_dev = 0;
    if (opt.one_filesystem) {
        struct stat st{};
        if (::lstat(res.root.c_str(), &st) == 0) root_dev = st.st_dev;
    }

    // The root itself is recorded as "." so a baseline always has an anchor.
    {
        Record r; r.path = ".";
        if (stat_into(res.root, r)) res.records.push_back(std::move(r));
    }

    auto it_opts = fs::directory_options::skip_permission_denied;
    if (opt.follow_symlinks) it_opts |= fs::directory_options::follow_directory_symlink;

    fs::recursive_directory_iterator it(canon, it_opts, ec), end;
    if (ec) throw Error("cannot open directory '" + res.root + "': " + ec.message());

    for (; it != end; it.increment(ec)) {
        if (ec) { res.warnings.push_back("iteration error: " + ec.message()); ec.clear(); continue; }
        const fs::path& p = it->path();
        std::string abs = p.string();

        Record r;
        r.path = fs::relative(p, canon, ec).generic_string();
        if (ec) { r.path = abs; ec.clear(); }

        if (path_excluded(r.path, opt.excludes)) {
            it.disable_recursion_pending();  // prune excluded directories
            continue;
        }

        if (!stat_into(abs, r)) {
            res.warnings.push_back("vanished or unreadable: " + abs);
            continue;
        }

        if (opt.one_filesystem && r.type == EntryType::Dir) {
            struct stat st{};
            if (::lstat(abs.c_str(), &st) == 0 && st.st_dev != root_dev) {
                it.disable_recursion_pending();  // do not descend into other mounts
                continue;
            }
        }

        if (r.type == EntryType::Symlink) {
            // Hash the link target string rather than chasing it.
            std::string target = fs::read_symlink(p, ec).string();
            if (ec) { target.clear(); ec.clear(); }
            r.hash = sha3(reinterpret_cast<const uint8_t*>(target.data()), target.size());
        }
        res.records.push_back(std::move(r));
    }

    std::sort(res.records.begin(), res.records.end());

    // ---- parallel content hashing of regular files --------------------------
    std::vector<size_t> todo;
    for (size_t i = 0; i < res.records.size(); ++i)
        if (res.records[i].type == EntryType::File) todo.push_back(i);

    unsigned nthreads = opt.threads ? opt.threads : std::thread::hardware_concurrency();
    if (nthreads == 0) nthreads = 1;
    nthreads = std::min<unsigned>(nthreads, (unsigned)std::max<size_t>(1, todo.size()));

    std::atomic<size_t> next{0};
    std::atomic<uint64_t> hashed{0};
    std::mutex warn_mu;

    auto worker = [&]() {
        for (;;) {
            size_t k = next.fetch_add(1);
            if (k >= todo.size()) break;
            Record& r = res.records[todo[k]];
            std::string abs = (canon / fs::path(r.path)).string();
            try {
                r.hash = sha3_file(abs);
                hashed.fetch_add(r.size);
            } catch (const std::exception& e) {
                std::lock_guard<std::mutex> lk(warn_mu);
                res.warnings.push_back(std::string("could not hash ") + r.path + ": " + e.what());
            }
        }
    };

    if (nthreads <= 1 || todo.size() <= 1) {
        worker();
    } else {
        std::vector<std::thread> pool;
        for (unsigned t = 0; t < nthreads; ++t) pool.emplace_back(worker);
        for (auto& th : pool) th.join();
    }
    res.bytes_hashed = hashed.load();

    for (const auto& r : res.records) {
        switch (r.type) {
            case EntryType::File:    res.files++;    break;
            case EntryType::Dir:     res.dirs++;     break;
            case EntryType::Symlink: res.symlinks++; break;
            default:                 res.others++;   break;
        }
    }
    return res;
}

} // namespace vigil
