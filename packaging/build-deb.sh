#!/bin/sh
set -eu

VERSION="${1:-0.1.0}"
ARCH="${2:-arm64}"
OUT_DIR="${3:-dist}"
BIN_PATH="${4:-}"

mkdir -p "$OUT_DIR"

CLEANUP_BIN=""
if [ -z "$BIN_PATH" ]; then
    BIN_PATH="$OUT_DIR/wolproxy-linux-$ARCH"
    CLEANUP_BIN="$BIN_PATH"
    CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$BIN_PATH" ./cmd/wolproxy
fi

STAGE_DIR="$(mktemp -d)"
trap 'rm -rf "$STAGE_DIR"; [ -n "$CLEANUP_BIN" ] && rm -f "$CLEANUP_BIN"' EXIT

mkdir -p \
    "$STAGE_DIR/DEBIAN" \
    "$STAGE_DIR/usr/bin" \
    "$STAGE_DIR/etc/wolproxy" \
    "$STAGE_DIR/lib/systemd/system"

chmod 0755 \
    "$STAGE_DIR" \
    "$STAGE_DIR/DEBIAN" \
    "$STAGE_DIR/usr" \
    "$STAGE_DIR/usr/bin" \
    "$STAGE_DIR/etc" \
    "$STAGE_DIR/etc/wolproxy" \
    "$STAGE_DIR/lib" \
    "$STAGE_DIR/lib/systemd" \
    "$STAGE_DIR/lib/systemd/system"

cp "$BIN_PATH" "$STAGE_DIR/usr/bin/wolproxy"
chmod 0755 "$STAGE_DIR/usr/bin/wolproxy"

tr -d '\r' < packaging/config.yaml > "$STAGE_DIR/etc/wolproxy/config.yaml"
chmod 0644 "$STAGE_DIR/etc/wolproxy/config.yaml"

tr -d '\r' < packaging/wolproxy.service > "$STAGE_DIR/lib/systemd/system/wolproxy.service"
chmod 0644 "$STAGE_DIR/lib/systemd/system/wolproxy.service"

for script in postinst prerm postrm; do
    tr -d '\r' < "packaging/$script" > "$STAGE_DIR/DEBIAN/$script"
    chmod 0755 "$STAGE_DIR/DEBIAN/$script"
done

printf '/etc/wolproxy/config.yaml\n' > "$STAGE_DIR/DEBIAN/conffiles"
chmod 0644 "$STAGE_DIR/DEBIAN/conffiles"

INSTALLED_KB="$(du -sk "$STAGE_DIR/usr" "$STAGE_DIR/etc" "$STAGE_DIR/lib" | awk '{s+=$1} END {print s}')"

cat > "$STAGE_DIR/DEBIAN/control" <<EOF
Package: wolproxy
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: Seowoo Kang <noreply@github.com>
Installed-Size: $INSTALLED_KB
Depends: nftables, systemd, adduser
Recommends: wireguard-tools
Description: Transparent TCP Wake-on-LAN proxy and TUI editor
 wolproxy intercepts configured TCP ports arriving on trusted ingress
 interfaces (such as WireGuard) via nftables, wakes sleeping LAN targets
 with Wake-on-LAN magic packets when needed, and relays TCP streams.
EOF
chmod 0644 "$STAGE_DIR/DEBIAN/control"

(
    cd "$STAGE_DIR"
    md5sum usr/bin/wolproxy etc/wolproxy/config.yaml lib/systemd/system/wolproxy.service > DEBIAN/md5sums
    chmod 0644 DEBIAN/md5sums
)

DEB_FILE="$OUT_DIR/wolproxy_${VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group -Zgzip "$STAGE_DIR" "$DEB_FILE"
