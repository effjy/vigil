// vigil — a post-quantum file-integrity monitor (CLI).
#include "util.hpp"
#include "scan.hpp"
#include "baseline.hpp"
#include "keystore.hpp"
#include "pqsig.hpp"
#include "watch.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <ctime>
#include <unistd.h>

#ifndef VIGIL_VERSION
#define VIGIL_VERSION "0.0.0"
#endif

using namespace vigil;

namespace {

// Exit codes. `check` distinguishes "drift" and "bad signature" so cron jobs
// and alerting can react differently.
enum Exit { OK = 0, USAGE = 1, DRIFT = 2, BAD_SIG = 4 };

bool g_color = false;
const char* C_RED   = "";
const char* C_GREEN = "";
const char* C_YEL   = "";
const char* C_DIM   = "";
const char* C_RST   = "";

void init_color() {
    g_color = ::isatty(STDOUT_FILENO) && !std::getenv("NO_COLOR");
    if (g_color) {
        C_RED="\033[31m"; C_GREEN="\033[32m"; C_YEL="\033[33m";
        C_DIM="\033[2m"; C_RST="\033[0m";
    }
}

// Minimal flag parser: pulls `--name value` / `-n value` and boolean flags out
// of argv, leaving positional args in `pos`.
struct Args {
    std::map<std::string,std::string> opt;                       // last value wins
    std::map<std::string,std::vector<std::string>> multi;        // every occurrence
    std::map<std::string,bool> flag;
    std::vector<std::string> pos;

    std::string get(const std::string& k, const std::string& def="") const {
        auto it = opt.find(k); return it==opt.end()?def:it->second;
    }
    const std::vector<std::string>& all(const std::string& k) const {
        static const std::vector<std::string> empty;
        auto it = multi.find(k); return it==multi.end()?empty:it->second;
    }
    bool has(const std::string& k) const { return opt.count(k) || flag.count(k); }
};

// `value_opts` lists the option names that consume a following argument.
Args parse(int argc, char** argv, int start,
           const std::map<std::string,std::string>& aliases,
           const std::vector<std::string>& value_opts) {
    Args a;
    auto wants_value = [&](const std::string& n){
        return std::find(value_opts.begin(), value_opts.end(), n) != value_opts.end();
    };
    for (int i = start; i < argc; ++i) {
        std::string s = argv[i];
        if (s.size() >= 1 && s[0] == '-' && s != "-") {
            // Support --name=value for long options.
            std::string inline_val;
            bool has_inline = false;
            if (s.rfind("--", 0) == 0) {
                auto eq = s.find('=');
                if (eq != std::string::npos) {
                    inline_val = s.substr(eq + 1);
                    s = s.substr(0, eq);
                    has_inline = true;
                }
            }
            std::string name = s;
            auto ai = aliases.find(s);
            if (ai != aliases.end()) name = ai->second;
            // strip leading dashes for storage key
            std::string key = name;
            while (!key.empty() && key[0]=='-') key.erase(key.begin());
            if (wants_value(key)) {
                std::string val;
                if (has_inline) {
                    val = inline_val;
                } else {
                    if (i+1 >= argc) throw Error("option '" + s + "' needs a value");
                    val = argv[++i];
                }
                a.opt[key] = val;
                a.multi[key].push_back(val);
            } else if (has_inline) {
                throw Error("option '" + s + "' does not take a value");
            } else {
                a.flag[key] = true;
            }
        } else {
            a.pos.push_back(s);
        }
    }
    return a;
}

std::string get_passphrase(bool confirm) {
    if (const char* e = std::getenv("VIGIL_PASSPHRASE")) return std::string(e);
    return prompt_passphrase(confirm ? "New passphrase: " : "Passphrase: ", confirm);
}

ScanOptions scan_opts_from(const Args& a) {
    ScanOptions o;
    o.follow_symlinks = a.flag.count("follow-symlinks");
    o.one_filesystem  = a.flag.count("one-file-system");
    if (a.opt.count("jobs")) o.threads = (unsigned)std::stoul(a.get("jobs"));
    return o;
}

// Gather --exclude patterns plus those from an --exclude-from file (one pattern
// per line; blank lines and '#' comments ignored).
std::vector<std::string> gather_excludes(const Args& a) {
    std::vector<std::string> ex = a.all("exclude");
    if (a.has("exclude-from")) {
        Bytes raw = read_file(a.get("exclude-from"));
        std::string line;
        auto flush = [&]{
            size_t b = line.find_first_not_of(" \t\r");
            size_t e = line.find_last_not_of(" \t\r");
            if (b != std::string::npos) {
                std::string t = line.substr(b, e - b + 1);
                if (!t.empty() && t[0] != '#') ex.push_back(t);
            }
            line.clear();
        };
        for (uint8_t c : raw) { if (c == '\n') flush(); else line.push_back((char)c); }
        flush();
    }
    return ex;
}

void print_scan_warnings(const ScanResult& s) {
    for (const auto& w : s.warnings)
        std::fprintf(stderr, "%swarning:%s %s\n", C_YEL, C_RST, w.c_str());
}

// ---- subcommands ----------------------------------------------------------

int cmd_keygen(int argc, char** argv) {
    Args a = parse(argc, argv, 2,
        {{"-a","--alg"},{"-k","--key"},{"-p","--pub"}},
        {"alg","key","pub"});
    std::string alg = a.get("alg", kDefaultSigAlg);
    std::string keypath = a.get("key", "vigil.key");
    std::string pubpath = a.get("pub", "vigil.pub");

    std::string canon = sig_canonical_alg(alg);  // validate early
    std::string pass = get_passphrase(/*confirm=*/true);
    keystore_generate(canon, keypath, pubpath, pass);
    secure_wipe(pass.data(), pass.size());

    std::fprintf(stderr,
        "%s✓%s generated %s keypair\n  secret: %s (encrypted, 0600)\n  public: %s\n",
        C_GREEN, C_RST, canon.c_str(), keypath.c_str(), pubpath.c_str());
    return OK;
}

int cmd_baseline(int argc, char** argv) {
    Args a = parse(argc, argv, 2,
        {{"-k","--key"},{"-o","--out"},{"-j","--jobs"},{"-x","--exclude"}},
        {"key","out","jobs","prev","prev-pub","alg","exclude","exclude-from"});
    if (a.pos.empty()) throw Error("usage: vigil baseline <path> [-k key] [-o out.vgl]");
    std::string path    = a.pos[0];
    std::string keypath = a.get("key", "vigil.key");
    std::string out     = a.get("out", "baseline.vgl");

    std::string pass = get_passphrase(/*confirm=*/false);
    KeyPair key = keystore_load_secret(keypath, pass);
    secure_wipe(pass.data(), pass.size());

    // Chain to a prior baseline, but only after verifying its signature so the
    // tamper-evident history is cryptographically self-checking. By default the
    // prior link must be signed by this same keypair; --prev-pub overrides that
    // for the key-rotation case.
    Bytes prev_root;
    if (a.has("prev")) {
        Baseline old = baseline_load(a.get("prev"));
        PublicKey trust = a.has("prev-pub")
            ? keystore_load_public(a.get("prev-pub"))
            : PublicKey{ key.alg, key.pub };
        if (!baseline_verify(old, trust))
            throw Error("refusing to chain: prior baseline '" + a.get("prev") +
                        "' fails signature verification" +
                        (a.has("prev-pub") ? "" : " against the current key "
                         "(use --prev-pub if it was signed by an older key)"));
        prev_root = old.merkle_root;
    }

    ScanOptions so = scan_opts_from(a);
    so.excludes = gather_excludes(a);
    ScanResult scan = scan_tree(path, so);
    print_scan_warnings(scan);

    Baseline b = baseline_build(scan, a.get("alg", key.alg), prev_root);
    baseline_sign(b, key);
    baseline_save(out, b);

    std::fprintf(stderr,
        "%s✓%s baseline written to %s\n"
        "  root:   %s\n"
        "  files:  %llu  dirs: %llu  symlinks: %llu  other: %llu\n"
        "  hashed: %llu bytes\n"
        "  exclude:%zu pattern(s)\n"
        "  merkle: %s%.16s…%s\n"
        "  signed: %s\n",
        C_GREEN, C_RST, out.c_str(), b.root.c_str(),
        (unsigned long long)scan.files, (unsigned long long)scan.dirs,
        (unsigned long long)scan.symlinks, (unsigned long long)scan.others,
        (unsigned long long)scan.bytes_hashed, b.excludes.size(),
        C_DIM, to_hex(b.merkle_root).c_str(), C_RST, b.alg.c_str());
    return OK;
}

int cmd_check(int argc, char** argv) {
    Args a = parse(argc, argv, 2,
        {{"-p","--pub"},{"-d","--db"},{"-j","--jobs"}},
        {"pub","db","jobs"});
    std::string pubpath = a.get("pub", "vigil.pub");
    std::string dbpath  = a.get("db", "baseline.vgl");
    bool quiet = a.flag.count("quiet");

    bool json = a.flag.count("json");

    Baseline b = baseline_load(dbpath);
    PublicKey pk = keystore_load_public(pubpath);

    bool sig_ok = baseline_verify(b, pk);
    std::string path = a.pos.empty() ? b.root : a.pos[0];

    if (!sig_ok && !json) {
        std::fprintf(stderr,
            "%s✗ SIGNATURE INVALID%s — the baseline '%s' has been tampered with "
            "or was signed by a different key. Refusing to trust it.\n",
            C_RED, C_RST, dbpath.c_str());
        return BAD_SIG;
    }

    std::vector<Change> changes;
    ScanResult scan;
    if (sig_ok) {
        // Apply the exact exclude set recorded in the baseline so the check
        // filters identically to how the baseline was built.
        ScanOptions so = scan_opts_from(a);
        so.excludes = b.excludes;
        scan = scan_tree(path, so);
        if (!json) print_scan_warnings(scan);
        changes = baseline_diff(b.records, scan.records);
    }

    size_t added=0, removed=0, modified=0;
    for (const auto& c : changes) {
        if (c.kind == Change::Kind::Added) added++;
        else if (c.kind == Change::Kind::Removed) removed++;
        else modified++;
    }

    if (json) {
        // One machine-readable object on stdout, suitable for SIEM ingestion.
        std::printf("{\"baseline\":\"%s\",\"root\":\"%s\",\"algorithm\":\"%s\","
                    "\"signature_valid\":%s,",
                    json_escape(dbpath).c_str(), json_escape(b.root).c_str(),
                    json_escape(b.alg).c_str(), sig_ok ? "true" : "false");
        std::printf("\"clean\":%s,\"changes\":[", (sig_ok && changes.empty()) ? "true":"false");
        for (size_t i = 0; i < changes.size(); ++i) {
            const Change& c = changes[i];
            std::printf("%s{\"kind\":\"%s\",\"path\":\"%s\"",
                        i ? "," : "", change_kind_name(c.kind),
                        json_escape(c.path).c_str());
            if (!c.detail.empty())
                std::printf(",\"detail\":\"%s\"", json_escape(c.detail).c_str());
            std::printf("}");
        }
        std::printf("],\"summary\":{\"added\":%zu,\"removed\":%zu,\"modified\":%zu}}\n",
                    added, removed, modified);
        std::fflush(stdout);
        if (!sig_ok) return BAD_SIG;
        return changes.empty() ? OK : DRIFT;
    }

    if (changes.empty()) {
        std::fprintf(stderr, "%s✓%s no changes — %zu objects match the signed baseline\n",
                     C_GREEN, C_RST, b.records.size());
        return OK;
    }
    for (const auto& c : changes) {
        const char* sym; const char* col;
        switch (c.kind) {
            case Change::Kind::Added:    sym="+"; col=C_GREEN; break;
            case Change::Kind::Removed:  sym="-"; col=C_RED;   break;
            default:                     sym="~"; col=C_YEL;   break;
        }
        if (!quiet) {
            if (c.kind == Change::Kind::Modified)
                std::printf("%s%s%s %s %s(%s)%s\n", col, sym, C_RST,
                            c.path.c_str(), C_DIM, c.detail.c_str(), C_RST);
            else
                std::printf("%s%s%s %s\n", col, sym, C_RST, c.path.c_str());
        }
    }
    std::fprintf(stderr,
        "%s⚠ drift detected%s — %s+%zu%s added, %s-%zu%s removed, %s~%zu%s modified\n",
        C_YEL, C_RST, C_GREEN, added, C_RST, C_RED, removed, C_RST, C_YEL, modified, C_RST);
    return DRIFT;
}

int cmd_watch(int argc, char** argv) {
    Args a = parse(argc, argv, 2,
        {{"-p","--pub"},{"-d","--db"},{"-j","--jobs"}},
        {"pub","db","jobs","debounce","resweep"});
    std::string pubpath = a.get("pub", "vigil.pub");
    std::string dbpath  = a.get("db", "baseline.vgl");

    Baseline b = baseline_load(dbpath);
    PublicKey pk = keystore_load_public(pubpath);
    if (!baseline_verify(b, pk)) {
        std::fprintf(stderr, "%s✗ signature INVALID%s for '%s' — refusing to watch\n",
                     C_RED, C_RST, dbpath.c_str());
        return BAD_SIG;
    }

    WatchOptions opt;
    opt.scan = scan_opts_from(a);
    opt.scan.excludes = b.excludes;   // filter identically to the baseline
    opt.json = a.flag.count("json");
    if (a.opt.count("debounce")) opt.debounce_ms = std::stoi(a.get("debounce"));
    if (a.opt.count("resweep"))  opt.resweep_sec = std::stoi(a.get("resweep"));

    std::string path = a.pos.empty() ? b.root : a.pos[0];
    return watch_run(b, path, opt);
}

int cmd_verify(int argc, char** argv) {
    Args a = parse(argc, argv, 2, {{"-p","--pub"},{"-d","--db"}}, {"pub","db"});
    std::string pubpath = a.get("pub", "vigil.pub");
    std::string dbpath  = a.get("db", "baseline.vgl");

    Baseline b = baseline_load(dbpath);
    PublicKey pk = keystore_load_public(pubpath);
    if (!baseline_verify(b, pk)) {
        std::fprintf(stderr, "%s✗ signature INVALID%s for '%s'\n", C_RED, C_RST, dbpath.c_str());
        return BAD_SIG;
    }
    std::fprintf(stderr, "%s✓ signature valid%s (%s) — %zu objects, merkle %.16s…\n",
                 C_GREEN, C_RST, b.alg.c_str(), b.records.size(),
                 to_hex(b.merkle_root).c_str());
    return OK;
}

int cmd_show(int argc, char** argv) {
    Args a = parse(argc, argv, 2, {{"-d","--db"}}, {"db"});
    std::string dbpath = a.get("db", "baseline.vgl");
    Baseline b = baseline_load(dbpath);

    char when[64]; std::time_t t=(std::time_t)b.created;
    std::strftime(when, sizeof when, "%Y-%m-%d %H:%M:%S %z", std::localtime(&t));

    std::printf("baseline:    %s\n", dbpath.c_str());
    std::printf("root:        %s\n", b.root.c_str());
    std::printf("created:     %s\n", when);
    std::printf("algorithm:   %s\n", b.alg.c_str());
    std::printf("objects:     %zu\n", b.records.size());
    std::printf("merkle root: %s\n", to_hex(b.merkle_root).c_str());
    bool chained = std::any_of(b.prev_root.begin(), b.prev_root.end(), [](uint8_t x){return x!=0;});
    std::printf("prev root:   %s\n", chained ? to_hex(b.prev_root).c_str() : "(none)");
    if (a.flag.count("list")) {
        for (const auto& r : b.records)
            std::printf("  %-8s %06o %s\n", entry_type_name(r.type), r.mode & 07777, r.path.c_str());
    }
    return OK;
}

void usage() {
    std::printf(
        "vigil %s — post-quantum file-integrity monitor\n\n"
        "USAGE\n"
        "  vigil keygen   [-a ALG] [-k vigil.key] [-p vigil.pub]\n"
        "  vigil baseline <path> [-k vigil.key] [-o baseline.vgl]\n"
        "                 [--prev OLD.vgl [--prev-pub OLD.pub]]\n"
        "                 [-x GLOB ...] [--exclude-from FILE]\n"
        "                 [-j N] [--one-file-system] [--follow-symlinks]\n"
        "  vigil check    [<path>] [-p vigil.pub] [-d baseline.vgl] [-j N] [--quiet] [--json]\n"
        "  vigil watch    [<path>] [-p vigil.pub] [-d baseline.vgl] [--json] [--resweep S]\n"
        "  vigil verify   [-p vigil.pub] [-d baseline.vgl]\n"
        "  vigil show     [-d baseline.vgl] [--list]\n"
        "  vigil version\n\n"
        "The secret key is encrypted at rest (Argon2id + AES-256-GCM); set\n"
        "VIGIL_PASSPHRASE to run non-interactively. Baselines are signed with\n"
        "ML-DSA (FIPS 204). 'check'/'watch' need only the public key. 'check'\n"
        "exit codes: 0 clean, 2 drift, 4 bad signature.\n",
        VIGIL_VERSION);
}

} // namespace

int main(int argc, char** argv) {
    init_color();
    if (argc < 2) { usage(); return USAGE; }
    std::string cmd = argv[1];
    try {
        if (cmd == "keygen")   return cmd_keygen(argc, argv);
        if (cmd == "baseline") return cmd_baseline(argc, argv);
        if (cmd == "check")    return cmd_check(argc, argv);
        if (cmd == "watch")    return cmd_watch(argc, argv);
        if (cmd == "verify")   return cmd_verify(argc, argv);
        if (cmd == "show")     return cmd_show(argc, argv);
        if (cmd == "version" || cmd == "--version" || cmd == "-V") {
            std::printf("vigil %s\n", VIGIL_VERSION); return OK;
        }
        if (cmd == "help" || cmd == "--help" || cmd == "-h") { usage(); return OK; }
        std::fprintf(stderr, "vigil: unknown command '%s' (try 'vigil help')\n", cmd.c_str());
        return USAGE;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "%svigil: %s%s\n", C_RED, e.what(), C_RST);
        return USAGE;
    }
}
