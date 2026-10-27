#!/usr/bin/env bash
# Native paired build. Optional second argument builds a stable tagged release.
# Neither mode publishes anything.
set -euo pipefail
export LC_ALL=C
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo"
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]]
# shellcheck source=/dev/null
source /etc/os-release
[[ $ID:$VERSION_ID == ubuntu:24.04 ]]
[[ $(getconf GNU_LIBC_VERSION) == 'glibc 2.39' ]]
[[ $(go env GOHOSTOS)/$(go env GOHOSTARCH) == linux/amd64 ]]
[[ $# -ge 1 && $# -le 2 && $1 == /* && ! -e $1 ]] || { echo 'Pass a new absolute output directory and optional release tag' >&2; exit 1; }
git diff --quiet HEAD || { echo 'Candidate requires a clean, committed checkout' >&2; exit 1; }
[[ -z $(git ls-files --others --exclude-standard) ]] || { echo 'Candidate requires a clean, committed checkout' >&2; exit 1; }
commit=$(git rev-parse HEAD)
version="0.0.0-candidate.$commit"
root="nocklock-candidate-$commit-linux-amd64"
tag=${2:-}
if [[ -n "$tag" ]]; then
  [[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
  [[ $(git rev-parse "$tag^{commit}") == "$commit" ]]
  git merge-base --is-ancestor "$commit" origin/main
  version=${tag#v}
  root="nocklock-$tag-linux-amd64"
fi
mkdir -m 0755 "$1"
out=$1
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
mkdir "$stage/$root"
pkg="$stage/$root"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags "-X github.com/nocktechnologies/nocklock/internal/version.Version=$version" \
  -o "$pkg/nocklock" ./cmd/nocklock
/usr/bin/gcc -shared -fPIC -Wall -Wextra -Werror -O2 \
  -o "$pkg/libfence_fs.so" internal/fence/fs/interposer/libfence_fs.c -ldl -lpthread
if [[ -z "$tag" ]]; then
  install -m 0755 scripts/install-egress-helper.sh "$pkg/install-egress-helper.sh"
  install -m 0644 packaging/linux/INSTALL.md "$pkg/"
else
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$out/nocklock-install-linux-amd64" ./cmd/nocklock-install
  install -m 0644 packaging/linux/RELEASE-INSTALL.md "$pkg/INSTALL.md"
fi
install -m 0644 LICENSE "$pkg/"
"$pkg/nocklock" version
python3 - "$pkg" "$out" "$commit" "$(git show -s --format=%ct HEAD)" "$tag" <<'PY'
import hashlib, json, os, pathlib, re, subprocess, sys, tarfile
pkg, out = map(pathlib.Path, sys.argv[1:3])
commit, epoch = sys.argv[3], int(sys.argv[4])
tag = sys.argv[5]
def output(*args):
    return subprocess.check_output(args, text=True).strip()
elf = {}
for name in ("nocklock", "libfence_fs.so"):
    path = str(pkg / name)
    headers = output('/usr/bin/readelf', '-h', path)
    if not re.search(r'Machine:\s+Advanced Micro Devices X86-64', headers):
        raise SystemExit('unexpected ELF architecture')
    versions = sorted(set(re.findall(r'GLIBC_([0-9.]+)', output('/usr/bin/readelf', '--version-info', path))))
    if any(tuple(map(int, value.split('.'))) > (2, 39) for value in versions):
        raise SystemExit('GLIBC symbol requirement exceeds Ubuntu 24.04 baseline')
    elf[name] = {'glibc_versions': versions, 'dynamic': output('/usr/bin/readelf', '-d', path)}
info = dict(schema=1, kind='ci-candidate-not-release', commit=commit,
            version='0.0.0-candidate.' + commit, os='linux', arch='amd64',
            distribution='ubuntu-24.04', libc_baseline='glibc-2.39',
            go=output('go', 'version'), c_compiler=output('/usr/bin/gcc', '--version'),
            builder_image=os.environ.get('ImageVersion', 'unrecorded'),
            source_date_epoch=epoch, elf=elf,
            files={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(pkg.iterdir())})
if tag:
    info.update(kind='release', tag=tag, version=tag[1:], install_protocol=1)
(pkg / 'build-info.json').write_text(json.dumps(info, indent=2, sort_keys=True) + '\n')
archive = out / (f'nocklock_{tag}_linux_amd64.tar.gz' if tag else pkg.name + '.tar.gz')
with tarfile.open(archive, 'w:gz', format=tarfile.USTAR_FORMAT) as tar:
    for path in [pkg, *sorted(pkg.iterdir())]:
        entry = tar.gettarinfo(str(path), arcname=str(path.relative_to(pkg.parent)))
        entry.uid = entry.gid = 0
        entry.uname = entry.gname = ''
        entry.mtime = epoch
        entry.mode = 0o755 if path.is_dir() or path.name in ('nocklock', 'libfence_fs.so', 'install-egress-helper.sh') else 0o644
        if path.is_file():
            with path.open('rb') as data: tar.addfile(entry, data)
        else: tar.addfile(entry)
(out / 'SHA256SUMS').write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + '  ' + archive.name + '\n')
if tag:
    installer = out / 'nocklock-install-linux-amd64'
    (out / 'INSTALLER.SHA256SUMS').write_text(hashlib.sha256(installer.read_bytes()).hexdigest() + '  ' + installer.name + '\n')
PY
if [[ -z "$tag" ]]; then
  python3 packaging/linux/artifact.py "$out/$root.tar.gz" "$out/SHA256SUMS" "$commit"
else
  NOCKLOCK_TEST_RELEASE_DIR="$out" NOCKLOCK_TEST_RELEASE_TAG="$tag" \
    go test -count=1 ./internal/linuxinstall ./internal/installstate
fi
