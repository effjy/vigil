// vigil — live monitoring with inotify.
//
// `watch` loads a signed baseline, verifies it once, then watches the tree and
// reports drift against the baseline as it happens. It needs only the public
// key: the secret key stays offline.
#ifndef VIGIL_WATCH_HPP
#define VIGIL_WATCH_HPP

#include "baseline.hpp"
#include "scan.hpp"

namespace vigil {

struct WatchOptions {
    ScanOptions scan;
    bool        json = false;        // emit JSONL events on stdout
    int         debounce_ms = 800;   // settle time after the first event
    int         resweep_sec = 0;     // optional periodic full re-scan (0 = off)
};

// Blocks until SIGINT/SIGTERM. Returns 0 on clean shutdown. `root` defaults to
// the baseline's recorded root when empty.
int watch_run(const Baseline& baseline, const std::string& root,
              const WatchOptions& opt);

} // namespace vigil

#endif
