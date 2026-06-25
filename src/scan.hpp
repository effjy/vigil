// vigil — walk a directory tree into a deterministic set of records.
#ifndef VIGIL_SCAN_HPP
#define VIGIL_SCAN_HPP

#include "util.hpp"
#include <string>
#include <vector>
#include <cstdint>

namespace vigil {

enum class EntryType : uint8_t { File = 0, Dir = 1, Symlink = 2, Other = 3 };

// One filesystem object. `path` is stored relative to the scan root so a
// baseline stays valid if the whole tree is moved. For regular files `hash`
// is SHA3-512 of the contents; for symlinks it is SHA3-512 of the link
// target; for directories/other it is all-zero.
struct Record {
    std::string path;
    EntryType   type  = EntryType::Other;
    uint32_t    mode  = 0;   // permission + type bits from lstat
    uint32_t    uid   = 0;
    uint32_t    gid   = 0;
    uint64_t    size  = 0;
    int64_t     mtime = 0;   // seconds since epoch
    Bytes       hash;        // kHashLen bytes, or empty if unhashed

    bool operator<(const Record& o) const { return path < o.path; }
};

struct ScanOptions {
    bool     follow_symlinks = false;  // never traverse into symlinked dirs
    bool     one_filesystem  = false;  // do not cross mount points
    unsigned threads = 0;              // 0 => hardware_concurrency()
    // Glob patterns (fnmatch) of relative paths to skip; matched directories
    // are pruned (not descended into). A pattern with no '/' matches any path
    // component (so "*.log" or "cache" match anywhere); a pattern with '/'
    // matches the full relative path or any ancestor prefix.
    std::vector<std::string> excludes;
};

struct ScanResult {
    std::string              root;     // absolute, canonical scan root
    std::vector<std::string> excludes; // the exclude patterns that were applied
    std::vector<Record> records;       // sorted by path
    uint64_t            bytes_hashed = 0;
    uint64_t            files = 0, dirs = 0, symlinks = 0, others = 0;
    std::vector<std::string> warnings; // unreadable entries, etc.
};

// Walk `root`, returning records sorted by path. Unreadable entries are
// recorded as warnings rather than aborting the scan.
ScanResult scan_tree(const std::string& root, const ScanOptions& opt);

// Build a single record (metadata + content/symlink hash) for the object at
// absolute path `abs`, storing `relpath` in Record::path. Returns false if the
// object does not exist. A transient hashing error leaves Record::hash empty
// rather than throwing, so live monitoring keeps running. This is the
// incremental counterpart to scan_tree used by `vigil watch`.
bool make_record(const std::string& abs, const std::string& relpath, Record& out);

const char* entry_type_name(EntryType t);

// True if `relpath` should be skipped given the exclude patterns. Used by both
// the full scan and the incremental watcher so they filter identically.
bool path_excluded(const std::string& relpath,
                   const std::vector<std::string>& patterns);

} // namespace vigil

#endif
