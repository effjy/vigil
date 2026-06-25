#!/usr/bin/env bash
# End-to-end smoke test for vigil. Builds nothing; expects ../vigil to exist.
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
VIGIL="$HERE/vigil"
export VIGIL_PASSPHRASE="correct horse battery staple"
NO_COLOR=1; export NO_COLOR

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

pass=0; fail=0
ok()   { echo "  ok   - $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL - $1"; fail=$((fail+1)); }
# expect <wanted-code> <label> <cmd...>
expect() { local want=$1 label=$2; shift 2; "$@" >out.log 2>&1; local got=$?; \
           [ "$got" = "$want" ] && ok "$label" || { bad "$label (want $want got $got)"; sed 's/^/      /' out.log; }; }

# --- fixture tree ---
mkdir -p tree/sub
echo "hello"      > tree/a.txt
echo "world"      > tree/sub/b.txt
ln -s a.txt         tree/link
chmod 0640        tree/sub/b.txt

echo "== keygen =="
expect 0 "keygen creates keypair" "$VIGIL" keygen -k k.key -p k.pub
[ -f k.key ] && ok "secret key file exists" || bad "secret key file missing"
[ -f k.pub ] && ok "public key file exists" || bad "public key file missing"
perm=$(stat -c %a k.key); [ "$perm" = "600" ] && ok "secret key is 0600" || bad "secret key perms = $perm"

echo "== baseline =="
expect 0 "baseline of clean tree" "$VIGIL" baseline tree -k k.key -o base.vgl
[ -f base.vgl ] && ok "baseline file exists" || bad "baseline file missing"

echo "== verify / check (clean) =="
expect 0 "signature verifies"          "$VIGIL" verify -p k.pub -d base.vgl
expect 0 "check reports no drift"      "$VIGIL" check tree -p k.pub -d base.vgl

echo "== drift detection =="
echo "tampered" >> tree/a.txt
expect 2 "modified file -> drift (2)"  "$VIGIL" check tree -p k.pub -d base.vgl
grep -q "a.txt" out.log && ok "modified path reported" || bad "modified path not reported"
git diff >/dev/null 2>&1 # noop

echo "blah" > tree/new.txt
expect 2 "added file still drift (2)"  "$VIGIL" check tree -p k.pub -d base.vgl
grep -q "new.txt" out.log && ok "added path reported" || bad "added path not reported"

rm tree/sub/b.txt
expect 2 "removed file still drift"    "$VIGIL" check tree -p k.pub -d base.vgl
grep -q "sub/b.txt" out.log && ok "removed path reported" || bad "removed path not reported"

echo "== re-baseline clears drift =="
expect 0 "re-baseline new state" "$VIGIL" baseline tree -k k.key -o base2.vgl --prev base.vgl
expect 0 "check against new baseline clean" "$VIGIL" check tree -p k.pub -d base2.vgl
"$VIGIL" show -d base2.vgl 2>&1 | grep -q "prev root:   [0-9a-f]" && ok "chain to prev recorded" || bad "prev root not chained"

echo "== --prev verifies the prior baseline's signature =="
# tamper with a prior baseline, then try to chain onto it -> must be refused
cp base.vgl forged.vgl
python3 - "$PWD/forged.vgl" <<'PY'
import sys
d=bytearray(open(sys.argv[1],'rb').read()); d[len(d)//2]^=0x01
open(sys.argv[1],'wb').write(d)
PY
expect 1 "chaining onto a tampered prior baseline is refused" \
  "$VIGIL" baseline tree -k k.key -o base3.vgl --prev forged.vgl
[ -f base3.vgl ] && bad "baseline was written despite bad prev" || ok "no baseline written when prev is bad"
# a prior baseline signed by a different key needs --prev-pub
"$VIGIL" keygen -k other.key -p other.pub >/dev/null 2>&1
"$VIGIL" baseline tree -k other.key -o otherbase.vgl >/dev/null 2>&1
expect 1 "prev signed by other key refused without --prev-pub" \
  "$VIGIL" baseline tree -k k.key -o base4.vgl --prev otherbase.vgl
expect 0 "prev signed by other key accepted with --prev-pub" \
  "$VIGIL" baseline tree -k k.key -o base4.vgl --prev otherbase.vgl --prev-pub other.pub

echo "== tamper with the baseline itself =="
cp base2.vgl tampered.vgl
# flip a byte in the middle of the signed body
python3 - "$PWD/tampered.vgl" <<'PY'
import sys
p=sys.argv[1]
d=bytearray(open(p,'rb').read())
i=len(d)//2
d[i]^=0x01
open(p,'wb').write(d)
PY
expect 4 "tampered baseline -> bad signature (4)" "$VIGIL" check tree -p k.pub -d tampered.vgl

echo "== wrong key rejected =="
"$VIGIL" keygen -k other.key -p other.pub >/dev/null 2>&1
expect 4 "other key fails verification" "$VIGIL" verify -p other.pub -d base2.vgl

echo "== option parsing (--name=value) =="
expect 0 "verify accepts --pub=/--db= inline values" "$VIGIL" verify --pub=k.pub --db=base2.vgl
expect 1 "boolean flag rejects =value" "$VIGIL" verify --quiet=oops -p k.pub -d base2.vgl
# silent-default regression: a typo'd value must NOT fall back silently
"$VIGIL" verify --db=does-not-exist.vgl -p k.pub >out.log 2>&1
[ $? != 0 ] && ok "--db= points at the given file (no silent default)" || bad "--db= ignored, used default"

echo "== wrong-algorithm key is invalid, not an error =="
"$VIGIL" keygen -a ml-dsa-87 -k k87.key -p k87.pub >/dev/null 2>&1
expect 4 "ml-dsa-87 key fails on ml-dsa-65 baseline" "$VIGIL" verify -p k87.pub -d base2.vgl
"$VIGIL" check tree -p k87.pub -d base2.vgl --json >ja.log 2>/dev/null
[ $? = 4 ] && ok "check --json wrong-alg exit 4" || bad "check --json wrong-alg exit"
python3 -c 'import json; d=json.load(open("ja.log")); assert d["signature_valid"] is False' 2>/dev/null \
  && ok "check --json wrong-alg emits valid JSON (signature_valid:false)" || { bad "wrong-alg json"; cat ja.log; }

echo "== exclude patterns =="
mkdir -p extree/proc extree/var/log extree/etc extree/cache
echo cpu  > extree/proc/cpuinfo
echo cfg  > extree/etc/app.conf
echo log  > extree/var/log/syslog
echo dat  > extree/cache/x.dat
printf 'cache\n# a comment\n\nvar/log\n' > excludes.txt
expect 0 "baseline with -x and --exclude-from" \
  "$VIGIL" baseline extree -k k.key -o ex.vgl -x proc --exclude-from excludes.txt
# excluded paths must not be in the baseline
"$VIGIL" show -d ex.vgl --list > exlist.log 2>&1
grep -qE 'proc|cache|var/log' exlist.log && bad "excluded paths leaked into baseline" || ok "proc/cache/var-log pruned from baseline"
grep -q 'etc/app.conf' exlist.log && ok "tracked path present in baseline" || bad "tracked path missing"
# mutating only excluded paths -> still clean (check reuses stored excludes)
echo changed > extree/proc/cpuinfo; echo more >> extree/var/log/syslog; rm extree/cache/x.dat; mkdir extree/cache/sub; echo y > extree/cache/sub/z
expect 0 "check ignores changes under excluded dirs (no -x needed)" \
  "$VIGIL" check extree -p k.pub -d ex.vgl
# mutating a tracked file -> drift
echo evil > extree/etc/app.conf
expect 2 "check still detects drift in tracked files" \
  "$VIGIL" check extree -p k.pub -d ex.vgl
grep -q 'etc/app.conf' out.log && ok "drift names the tracked file" || bad "tracked drift not named"

echo "== watch honors excludes =="
rm -rf extree/etc; mkdir -p extree/etc; echo cfg > extree/etc/app.conf   # reset tracked state
"$VIGIL" baseline extree -k k.key -o ex.vgl -x proc -x cache -x 'var/log' >/dev/null 2>&1
"$VIGIL" watch extree -p k.pub -d ex.vgl --json --debounce 150 >exwatch.log 2>/dev/null &
EWP=$!; sleep 1
echo noise > extree/cache/y.dat          # excluded -> must be ignored
echo noise > extree/proc/stat            # excluded -> must be ignored
echo real  > extree/etc/app.conf         # tracked -> must drift
sleep 1.5
kill -INT $EWP 2>/dev/null; wait $EWP 2>/dev/null
python3 - exwatch.log <<'PY' && ok "watch reports tracked file, ignores excluded ones" || { bad "watch exclude filtering"; sed 's/^/      /' exwatch.log; }
import json,sys
ev=[json.loads(l) for l in open(sys.argv[1]) if l.strip()]
paths={e["path"] for e in ev}
assert any(p=="etc/app.conf" for p in paths), f"tracked change missing: {paths}"
assert not any(p.startswith(("cache","proc","var/log")) for p in paths), f"excluded path leaked: {paths}"
PY

echo "== json output =="
# clean tree against base2 -> clean:true, exit 0
"$VIGIL" check tree -p k.pub -d base2.vgl --json >j.log 2>/dev/null
[ $? = 0 ] && ok "json clean exit 0" || bad "json clean exit"
grep -q '"clean":true' j.log && ok "json reports clean:true" || { bad "json clean field"; cat j.log; }
python3 -c 'import json,sys; json.load(open("j.log"))' 2>/dev/null && ok "json clean is valid JSON" || bad "json clean not parseable"
# introduce drift, expect exit 2 and a change object
echo "x" >> tree/a.txt
"$VIGIL" check tree -p k.pub -d base2.vgl --json >j2.log 2>/dev/null
[ $? = 2 ] && ok "json drift exit 2" || bad "json drift exit"
python3 - j2.log <<'PY' && ok "json drift parses + has modified a.txt" || bad "json drift content"
import json,sys
d=json.load(open(sys.argv[1]))
assert d["clean"] is False, d
assert any(c["path"]=="a.txt" and c["kind"]=="modified" for c in d["changes"]), d
assert d["summary"]["modified"]>=1, d
PY
# bad signature in json mode -> exit 4, signature_valid:false
"$VIGIL" check tree -p other.pub -d base2.vgl --json >j3.log 2>/dev/null
[ $? = 4 ] && ok "json bad-sig exit 4" || bad "json bad-sig exit"
grep -q '"signature_valid":false' j3.log && ok "json marks signature_valid:false" || bad "json sig field"

echo "== watch (live, incremental inotify) =="
# Use a fresh, clean tree so the watch test is isolated and deterministic.
mkdir -p wtree/sub; echo orig > wtree/keep.txt; echo b > wtree/sub/b.txt
"$VIGIL" baseline wtree -k k.key -o w.vgl >/dev/null 2>&1
"$VIGIL" check wtree -p k.pub -d w.vgl >/dev/null 2>&1 && ok "fresh watch tree starts clean" || bad "watch tree not clean at baseline"
"$VIGIL" watch wtree -p k.pub -d w.vgl --json --debounce 150 >watch.log 2>/dev/null &
WPID=$!
sleep 1
echo tampered > wtree/keep.txt              # modify existing file
mkdir -p wtree/newdir; echo hi > wtree/newdir/f.txt   # add file in a brand-new subdir
echo transient > wtree/tmp.txt              # add a file...
sleep 0.8
rm wtree/tmp.txt                            # ...then remove it -> fully resolves
sleep 1.5
kill -INT $WPID 2>/dev/null; wait $WPID 2>/dev/null

python3 -c 'import json; [json.loads(l) for l in open("watch.log") if l.strip()]' 2>/dev/null \
  && ok "watch output is valid JSONL" || { bad "watch JSONL invalid"; sed 's/^/      /' watch.log; }
python3 - watch.log <<'PY' && ok "watch drift on modified file" || bad "watch missed modified file"
import json,sys
ev=[json.loads(l) for l in open(sys.argv[1]) if l.strip()]
assert any(e["event"]=="drift" and e["path"]=="keep.txt" and e["kind"]=="modified" for e in ev), ev
PY
python3 - watch.log <<'PY' && ok "watch drift on file in new subdir (incremental recurse)" || bad "watch missed new subdir file"
import json,sys
ev=[json.loads(l) for l in open(sys.argv[1]) if l.strip()]
assert any(e["event"]=="drift" and e["path"]=="newdir/f.txt" and e["kind"]=="added" for e in ev), ev
PY
python3 - watch.log <<'PY' && ok "watch emits resolved when an added file is removed" || bad "watch missed resolved event"
import json,sys
ev=[json.loads(l) for l in open(sys.argv[1]) if l.strip()]
assert any(e["event"]=="drift" and e["path"]=="tmp.txt" and e["kind"]=="added" for e in ev), ev
assert any(e["event"]=="resolved" and e["path"]=="tmp.txt" for e in ev), ev
PY
# No phantom events: only the paths we actually touched should appear.
python3 - watch.log <<'PY' && ok "watch reports no phantom paths" || bad "watch emitted unexpected paths"
import json,sys
touched={"keep.txt","newdir/f.txt","newdir","tmp.txt"}
ev=[json.loads(l) for l in open(sys.argv[1]) if l.strip()]
extra={e["path"] for e in ev}-touched
assert not extra, f"unexpected paths: {extra}"
PY

echo "== watch resweep does not re-emit standing drift =="
mkdir -p rtree; echo a > rtree/x.txt
"$VIGIL" baseline rtree -k k.key -o r.vgl >/dev/null 2>&1
"$VIGIL" watch rtree -p k.pub -d r.vgl --json --debounce 100 --resweep 1 >rwatch.log 2>/dev/null &
RPID=$!
sleep 1
echo changed > rtree/x.txt          # one modification
sleep 3.5                            # let ~3 resweeps elapse
kill -INT $RPID 2>/dev/null; wait $RPID 2>/dev/null
python3 - rwatch.log <<'PY' && ok "standing drift emitted once despite repeated resweeps" || bad "resweep re-emitted drift"
import json,sys
ev=[json.loads(l) for l in open(sys.argv[1]) if l.strip()]
drifts=[e for e in ev if e.get("event")=="drift" and e["path"]=="x.txt"]
assert len(drifts)==1, f"expected 1 drift emission, got {len(drifts)}: {drifts}"
PY

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ]
