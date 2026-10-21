#!/usr/bin/env bash
# Boot a throwaway KVM guest from a verified cloud image for kernel-capability
# receipts. CI only: refuses anything but a GitHub-hosted runner, which is the
# disposable host. The guest is reachable as `ssh -F WORKDIR/ssh_config guest`,
# with a host key generated here and pinned, never trusted on first use.
#
# Usage: boot-guest.sh IMAGE WORKDIR
set -euo pipefail

test "${GITHUB_ACTIONS:-}" = true
test "${RUNNER_ENVIRONMENT:-}" = github-hosted
image="$1"
work="$2"
port=2222
mkdir -m 700 "$work"

ssh-keygen -q -t ed25519 -N '' -C abi9-client -f "$work/client"
ssh-keygen -q -t ed25519 -N '' -C abi9-guest -f "$work/hostkey"
{
  echo '#cloud-config'
  echo 'ssh_authorized_keys:'
  echo "  - $(cat "$work/client.pub")"
  echo 'ssh_genkeytypes: []'
  echo 'ssh_keys:'
  echo '  ed25519_private: |'
  sed 's/^/    /' "$work/hostkey"
  echo "  ed25519_public: $(cat "$work/hostkey.pub")"
  echo 'package_update: true'
  echo 'packages: [gcc, libc6-dev, git]'
} > "$work/user-data"
printf 'instance-id: nocklock-abi9\nlocal-hostname: abi9-guest\n' > "$work/meta-data"
cloud-localds "$work/seed.img" "$work/user-data" "$work/meta-data"
rm "$work/hostkey" "$work/user-data"

echo "[127.0.0.1]:$port $(cut -d' ' -f1,2 "$work/hostkey.pub")" > "$work/known_hosts"
cat > "$work/ssh_config" <<EOF
Host guest
  HostName 127.0.0.1
  Port $port
  User ubuntu
  IdentityFile $work/client
  IdentitiesOnly yes
  UserKnownHostsFile $work/known_hosts
  StrictHostKeyChecking yes
  ConnectTimeout 5
  BatchMode yes
EOF

qemu-img create -q -f qcow2 -F qcow2 -b "$image" "$work/disk.qcow2" 20G
qemu-system-x86_64 -enable-kvm -cpu host -smp "$(nproc)" -m 8192 \
  -drive "file=$work/disk.qcow2,if=virtio,format=qcow2" \
  -drive "file=$work/seed.img,if=virtio,format=raw" \
  -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$port-:22" -device virtio-net-pci,netdev=net0 \
  -display none -serial "file:$work/serial.log" -daemonize -pidfile "$work/qemu.pid"

up=false
for _ in $(seq 150); do
  if ssh -F "$work/ssh_config" guest true 2>/dev/null; then up=true; break; fi
  sleep 2
done
$up || { echo 'FAIL: guest SSH never came up' >&2; tail -50 "$work/serial.log" >&2; exit 1; }
# Exit 2 is "done with recoverable warnings"; the required tools are checked next.
ssh -F "$work/ssh_config" guest 'cloud-init status --wait --long' || test $? -eq 2
ssh -F "$work/ssh_config" guest 'command -v gcc && test -f /usr/include/linux/io_uring.h && command -v git && command -v python3'
