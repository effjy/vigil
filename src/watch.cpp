#include "watch.hpp"

#include <cstdio>
#include <cstring>
#include <cerrno>
#include <ctime>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <csignal>
#include <poll.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <filesystem>

namespace fs = std::filesystem;

namespace vigil {

namespace {

volatile sig_atomic_t g_stop = 0;
void on_signal(int) { g_stop = 1; }

const uint32_t WATCH_MASK =
    IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MOVED_FROM | IN_MOVED_TO |
    IN_CLOSE_WRITE | IN_ATTRIB | IN_MOVE_SELF;

std::string now_iso() {
    char buf[32];
    std::time_t t = std::time(nullptr);
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%S%z", std::localtime(&t));
    return buf;
}

// Recursively add inotify watches for `dir` and its subdirectories, skipping
// any directory excluded relative to `root`.
void add_watches(int ifd, const fs::path& root, const fs::path& dir,
                 const std::vector<std::string>& excludes,
                 std::unordered_map<int,std::string>& wd2path,
                 std::vector<std::string>& warnings) {
    int wd = inotify_add_watch(ifd, dir.c_str(), WATCH_MASK);
    if (wd >= 0) wd2path[wd] = dir.string();
    else { warnings.push_back("cannot watch " + dir.string() + ": " + std::strerror(errno)); return; }

    std::error_code ec;
    fs::recursive_directory_iterator it(
        dir, fs::directory_options::skip_permission_denied, ec), end;
    if (ec) return;
    for (; it != end; it.increment(ec)) {
        if (ec) { ec.clear(); continue; }
        std::string rel = it->path().lexically_relative(root).generic_string();
        if (path_excluded(rel, excludes)) { it.disable_recursion_pending(); continue; }
        if (it->is_directory(ec) && !it->is_symlink(ec)) {
            int w = inotify_add_watch(ifd, it->path().c_str(), WATCH_MASK);
            if (w >= 0) wd2path[w] = it->path().string();
        }
    }
}

// Current drift status of a single path relative to the baseline.
struct PathState {
    bool          drift = false;
    Change::Kind  kind  = Change::Kind::Modified;
    std::string   detail;
};

} // namespace

int watch_run(const Baseline& baseline, const std::string& root_in,
              const WatchOptions& opt) {
    std::error_code ec;
    fs::path rootp = fs::weakly_canonical(
        fs::path(root_in.empty() ? baseline.root : root_in), ec);
    if (ec) rootp = fs::path(root_in.empty() ? baseline.root : root_in);
    const std::string root = rootp.string();

    // The baseline is the trusted reference; index it by path. These pointers
    // are the only per-object memory we hold — there is no second copy of the
    // tree's live state.
    std::unordered_map<std::string, const Record*> bmap;
    bmap.reserve(baseline.records.size() * 2);
    for (const auto& r : baseline.records) bmap[r.path] = &r;

    // Only currently-drifted paths are remembered, so memory stays proportional
    // to the amount of drift, not to the size of the tree.
    std::unordered_map<std::string, std::string> drift;  // rel -> "kind\tdetail"

    auto rel_of = [&](const fs::path& abs) -> std::string {
        std::string r = abs.lexically_relative(rootp).generic_string();
        return (r.empty() || r == ".") ? "." : r;
    };
    auto abs_of = [&](const std::string& rel) -> std::string {
        return rel == "." ? root : (rootp / rel).string();
    };

    // --- inotify setup -------------------------------------------------------
    int ifd = inotify_init1(IN_NONBLOCK);
    if (ifd < 0) throw Error(std::string("inotify_init1 failed: ") + std::strerror(errno));
    std::unordered_map<int,std::string> wd2path;
    std::vector<std::string> warnings;
    add_watches(ifd, rootp, rootp, opt.scan.excludes, wd2path, warnings);
    for (const auto& w : warnings) std::fprintf(stderr, "warning: %s\n", w.c_str());

    struct sigaction sa{};
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    // --- emit helpers --------------------------------------------------------
    auto emit_drift = [&](const std::string& rel, Change::Kind k, const std::string& detail) {
        std::string ts = now_iso();
        if (opt.json) {
            std::printf("{\"ts\":\"%s\",\"event\":\"drift\",\"kind\":\"%s\",\"path\":\"%s\"",
                        ts.c_str(), change_kind_name(k), json_escape(rel).c_str());
            if (!detail.empty()) std::printf(",\"detail\":\"%s\"", json_escape(detail).c_str());
            std::printf("}\n");
        } else {
            const char* sym = k==Change::Kind::Added?"+":k==Change::Kind::Removed?"-":"~";
            if (detail.empty()) std::printf("[%s] %s %s\n", ts.c_str(), sym, rel.c_str());
            else std::printf("[%s] %s %s (%s)\n", ts.c_str(), sym, rel.c_str(), detail.c_str());
        }
    };
    auto emit_resolved = [&](const std::string& rel) {
        std::string ts = now_iso();
        if (opt.json)
            std::printf("{\"ts\":\"%s\",\"event\":\"resolved\",\"path\":\"%s\"}\n",
                        ts.c_str(), json_escape(rel).c_str());
        else
            std::printf("[%s] = %s (resolved)\n", ts.c_str(), rel.c_str());
    };

    // Fold a freshly computed state for `rel` into the drift map, emitting an
    // event only when its status actually changes.
    auto record_state = [&](const std::string& rel, const PathState& ps) {
        auto dit = drift.find(rel);
        bool was = dit != drift.end();
        if (!ps.drift) {
            if (was) { emit_resolved(rel); drift.erase(dit); }
            return;
        }
        std::string key = std::string(change_kind_name(ps.kind)) + "\t" + ps.detail;
        if (!was || dit->second != key) { emit_drift(rel, ps.kind, ps.detail); drift[rel] = key; }
    };

    // Re-stat (and, for files, re-hash) exactly one path and classify it.
    auto eval_path = [&](const std::string& rel) -> PathState {
        PathState ps;
        Record obs;
        bool present = make_record(abs_of(rel), rel, obs);
        auto it = bmap.find(rel);
        bool inbase = it != bmap.end();
        if (present && !inbase)       { ps.drift = true; ps.kind = Change::Kind::Added; }
        else if (!present && inbase)  { ps.drift = true; ps.kind = Change::Kind::Removed; }
        else if (present && inbase) {
            std::string d = record_compare(*it->second, obs);
            if (!d.empty()) { ps.drift = true; ps.kind = Change::Kind::Modified; ps.detail = d; }
        }
        return ps;
    };
    auto apply = [&](const std::string& rel) {
        if (path_excluded(rel, opt.scan.excludes)) return;  // never report excluded paths
        record_state(rel, eval_path(rel));
    };

    // --- initial reconciliation (one full scan) ------------------------------
    auto initial = [&]() {
        ScanResult s = scan_tree(root, opt.scan);
        if (!opt.json) for (const auto& w : s.warnings)
            std::fprintf(stderr, "warning: %s\n", w.c_str());
        std::unordered_set<std::string> seen;
        seen.reserve(s.records.size() * 2);
        for (const auto& obs : s.records) {
            seen.insert(obs.path);
            PathState ps;
            auto it = bmap.find(obs.path);
            if (it == bmap.end()) { ps.drift = true; ps.kind = Change::Kind::Added; }
            else {
                std::string d = record_compare(*it->second, obs);
                if (!d.empty()) { ps.drift = true; ps.kind = Change::Kind::Modified; ps.detail = d; }
            }
            record_state(obs.path, ps);
        }
        for (const auto& r : baseline.records)
            if (!seen.count(r.path)) {
                PathState ps; ps.drift = true; ps.kind = Change::Kind::Removed;
                record_state(r.path, ps);
            }
        // Reconcile any leftover drift the scan didn't touch — e.g. a file that
        // was added and then removed again while an inotify event was missed.
        // Such a path is in neither the scan nor the baseline, so without this
        // its stale "added" drift entry would never clear. Re-evaluating it
        // (it is now absent and not baselined) resolves it.
        std::vector<std::string> stale;
        for (const auto& kv : drift)
            if (!seen.count(kv.first) && !bmap.count(kv.first)) stale.push_back(kv.first);
        for (const auto& rel : stale) apply(rel);
    };

    if (!opt.json)
        std::fprintf(stderr, "vigil: watching %s (%zu objects baselined) — Ctrl-C to stop\n",
                     root.c_str(), baseline.records.size());
    initial();
    if (!opt.json && drift.empty())
        std::fprintf(stderr, "vigil: tree matches the signed baseline; watching for changes…\n");

    // --- event loop ----------------------------------------------------------
    std::vector<char> buf(64 * 1024);
    std::time_t last_sweep = std::time(nullptr);

    while (!g_stop) {
        struct pollfd pfd{ ifd, POLLIN, 0 };
        int timeout = opt.resweep_sec > 0 ? opt.resweep_sec * 1000 : 1000;
        int pr = ::poll(&pfd, 1, timeout);
        if (pr < 0) { if (errno == EINTR) continue; break; }

        // Paths touched in this debounce window; each is re-checked exactly once.
        std::unordered_set<std::string> affected;

        if (pr > 0 && (pfd.revents & POLLIN)) {
            for (;;) {
                ssize_t n = ::read(ifd, buf.data(), buf.size());
                if (n <= 0) {
                    if (n < 0 && errno == EAGAIN) {
                        struct pollfd p2{ ifd, POLLIN, 0 };
                        if (::poll(&p2, 1, opt.debounce_ms) > 0) continue;  // keep collecting
                    }
                    break;
                }
                for (ssize_t off = 0; off < n; ) {
                    auto* ev = reinterpret_cast<struct inotify_event*>(buf.data() + off);
                    auto wit = wd2path.find(ev->wd);
                    if (wit != wd2path.end()) {
                        fs::path dir = wit->second;
                        if (ev->len) {
                            fs::path child = dir / ev->name;
                            std::string crel = rel_of(child);
                            if (path_excluded(crel, opt.scan.excludes)) {
                                off += sizeof(struct inotify_event) + ev->len;
                                continue;
                            }
                            affected.insert(crel);
                            if (ev->mask & IN_ISDIR) {
                                if (ev->mask & (IN_CREATE | IN_MOVED_TO)) {
                                    // New subtree: watch it and check everything in it.
                                    std::vector<std::string> w;
                                    add_watches(ifd, rootp, child, opt.scan.excludes, wd2path, w);
                                    std::error_code e2;
                                    fs::recursive_directory_iterator di(
                                        child, fs::directory_options::skip_permission_denied, e2), de;
                                    for (; !e2 && di != de; di.increment(e2)) {
                                        if (e2) continue;
                                        std::string drel = rel_of(di->path());
                                        if (path_excluded(drel, opt.scan.excludes))
                                            { di.disable_recursion_pending(); continue; }
                                        affected.insert(drel);
                                    }
                                } else if (ev->mask & (IN_DELETE | IN_MOVED_FROM)) {
                                    // Subtree gone: re-check every baseline/drift path under it.
                                    std::string pref = crel + "/";
                                    for (const auto& kv : bmap)
                                        if (kv.first.compare(0, pref.size(), pref) == 0) affected.insert(kv.first);
                                    for (const auto& kv : drift)
                                        if (kv.first.compare(0, pref.size(), pref) == 0) affected.insert(kv.first);
                                }
                            }
                        } else {
                            // Event on the watched directory itself.
                            affected.insert(rel_of(dir));
                        }
                    }
                    if (ev->mask & IN_IGNORED) wd2path.erase(ev->wd);
                    off += sizeof(struct inotify_event) + ev->len;
                }
            }
        }

        for (const auto& rel : affected) apply(rel);

        std::time_t nowt = std::time(nullptr);
        if (opt.resweep_sec > 0 && (nowt - last_sweep) >= opt.resweep_sec) {
            // Safety net for anything inotify dropped under heavy churn.
            initial();
            last_sweep = nowt;
        }
        if (!affected.empty()) std::fflush(stdout);
    }

    ::close(ifd);
    if (!opt.json) std::fprintf(stderr, "\nvigil: stopped.\n");
    return 0;
}

} // namespace vigil
