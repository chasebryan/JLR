#!/usr/bin/env bash
# Builds the JLR boot artifacts under out/boot/:
#   initramfs.cpio.gz  init (stage 1) plus the trust anchors it will accept
#   base.sqfs          the read-only base image that is loaded into RAM
#   anchors.cbor       trust anchors (release public key)
#   release.key        release signing key       (TEST KEY: keep real keys offline)
#   other.key          a second release key that is NOT in the anchors (for negative tests)
#   busybox            static busybox used inside the base image
#
# Requirements: cargo with the x86_64-unknown-linux-musl target, mksquashfs, python3, gzip,
# and a static busybox (env JLR_BUSYBOX, else busybox-static on PATH, else extracted
# from the localhost/jlr-buildenv:dev container image).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${JLR_BOOT_OUT:-$ROOT/out/boot}"
TARGET=x86_64-unknown-linux-musl
BIN="$ROOT/target/$TARGET/release"
export PATH="$HOME/.cargo/bin:$PATH"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "build.sh: missing tool: $1" >&2; exit 3; }; }
need cargo; need mksquashfs; need python3; need gzip; need file

echo "==> building static binaries ($TARGET)"
(cd "$ROOT" && cargo build --release --target "$TARGET" -p jlr-boot -p jlr -p jlr-cell --locked 2>&1 | tail -1)

mkdir -p "$OUT"
rm -rf "$OUT/rootfs" "$OUT/initramfs"

find_busybox() {
  if [ -n "${JLR_BUSYBOX:-}" ]; then echo "$JLR_BUSYBOX"; return; fi
  if command -v busybox >/dev/null 2>&1 && file "$(command -v busybox)" | grep -q 'statically linked'; then command -v busybox; return; fi
  if command -v podman >/dev/null 2>&1 && podman image exists localhost/jlr-buildenv:dev 2>/dev/null; then
    podman run --rm localhost/jlr-buildenv:dev cat /usr/bin/busybox > "$OUT/busybox.extracted"
    chmod +x "$OUT/busybox.extracted"; echo "$OUT/busybox.extracted"; return
  fi
  echo "build.sh: no static busybox found; install busybox-static or set JLR_BUSYBOX" >&2; exit 3
}
BUSYBOX="$(find_busybox)"
file "$BUSYBOX" | grep -q 'statically linked' || { echo "build.sh: $BUSYBOX is not statically linked" >&2; exit 3; }
cp "$BUSYBOX" "$OUT/busybox"

echo "==> keys and trust anchors"
[ -f "$OUT/release.key" ] || "$BIN/jlr-release" keygen --role release --out "$OUT/release.key" >/dev/null
[ -f "$OUT/other.key" ]   || "$BIN/jlr-release" keygen --role release --out "$OUT/other.key" >/dev/null
"$BIN/jlr-release" pubkey "$OUT/release.key" --out "$OUT/release.pub" >/dev/null
"$BIN/jlr-release" anchors --out "$OUT/anchors.cbor" "$OUT/release.pub" >/dev/null

echo "==> base root filesystem"
R="$OUT/rootfs"
mkdir -p "$R"/{bin,sbin,usr/bin,usr/lib/jlr,etc,dev,proc,sys,run,tmp,mnt,var,lib,lib64}
cp "$OUT/busybox" "$R/bin/busybox"
for a in sh ash ls cat echo cp mv rm mkdir mount umount sleep true false id uname env grep sed tr wc head tail dmesg poweroff reboot ps kill test '[' date touch chmod ln readlink find printf df free; do
  ln -sf busybox "$R/bin/$a"
done
cp "$BIN/jlr-init" "$R/usr/lib/jlr/jlr-init"
ln -sf ../usr/lib/jlr/jlr-init "$R/sbin/init"
cp "$BIN/jlr" "$R/usr/bin/jlr"
cp "$BIN/jlr-cell-init" "$R/usr/bin/jlr-cell-init"
cp "$BIN/jlr-release" "$R/usr/bin/jlr-release"
cp "$ROOT/boot/guest-test.sh" "$R/usr/lib/jlr/guest-test.sh"
printf 'NAME="JLR base"\nID=jlr\nVERSION_ID=%s\n' "${JLR_VERSION:-0.1.0}" > "$R/etc/os-release"
printf 'root:x:0:0:root:/tmp:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/false\n' > "$R/etc/passwd"
printf 'root:x:0:\nnogroup:x:65534:\n' > "$R/etc/group"
: > "$R/etc/ld.so.cache"
find "$R" -exec touch -h -d @"$SOURCE_DATE_EPOCH" {} +

echo "==> squashfs image (reproducible)"
rm -f "$OUT/base.sqfs"
mksquashfs "$R" "$OUT/base.sqfs" -noappend -quiet -comp zstd -Xcompression-level 3 \
  -all-root -no-xattrs -reproducible >/dev/null   # timestamps come from SOURCE_DATE_EPOCH

echo "==> initramfs"
I="$OUT/initramfs"
mkdir -p "$I"/{etc/jlr,proc,sys,dev,mnt,newroot,run,tmp}
cp "$BIN/jlr-init" "$I/init"
cp "$OUT/anchors.cbor" "$I/etc/jlr/anchors.cbor"
find "$I" -exec touch -h -d @"$SOURCE_DATE_EPOCH" {} +
python3 "$ROOT/boot/mkcpio.py" "$I" | gzip -n -9 > "$OUT/initramfs.cpio.gz"

echo "==> artifacts in $OUT"
( cd "$OUT" && sha256sum base.sqfs initramfs.cpio.gz anchors.cbor | sed 's/^/    /' )
ls -la "$OUT/base.sqfs" "$OUT/initramfs.cpio.gz" | awk '{printf "    %10d  %s\n", $5, $9}'
