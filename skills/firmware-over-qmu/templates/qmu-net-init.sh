#!/bin/bash
# TEMPLATE: network-configuration init (PID 1), followed by foreground dropbear.
# QMU-NET-CONFIGURED is not SSH readiness; qmu must check the host-side connection.
# Injected tools live under /opt/qmu-tools. Boot WITHOUT --harness with:
#   --cmdline 'console=ttyAMA0 root=/dev/vda rw init=/qmu-net-init.sh net.ifnames=0'
export PATH=/opt/qmu-tools/bin:/bin:/sbin:/usr/bin:/usr/sbin
export LD_LIBRARY_PATH=/opt/qmu-tools/lib

mount -t proc     proc   /proc    2>/dev/null
mount -t sysfs    sys    /sys     2>/dev/null
mount -t devtmpfs dev    /dev     2>/dev/null
mkdir -p /dev/pts 2>/dev/null
mount -t devpts   devpts /dev/pts 2>/dev/null

# Recreate tmpfs mountpoints systemd would normally provide, so symlinks like
# /tmp -> /var/volatile/tmp resolve. Adjust to your firmware's layout (check readlink /tmp).
mount -t tmpfs tmpfs /var/volatile 2>/dev/null || true
mkdir -p /var/volatile/tmp /var/volatile/log 2>/dev/null
chmod 1777 /var/volatile/tmp 2>/dev/null

fail() {
    echo "QMU-NET-FAILED: $*" >&2
    while :; do sleep 5; done
}

# QEMU user-net: qmu sets gateway host=10.0.2.10; DHCP/hostfwd target is 10.0.2.15.
# Static config avoids depending on a busybox udhcpc default.script.
ip link set lo up || fail "link-lo"
ip link set eth0 up || fail "link-eth0"
ip addr add 10.0.2.15/24 dev eth0 || fail "address"
ip route add default via 10.0.2.10 || fail "route"

if address=$(ip -4 -o addr show dev eth0); then
    if [[ ! "$address" =~ (^|[[:space:]])inet[[:space:]]+10\.0\.2\.15/24([[:space:]]|$) ]]; then
        printf '%s\n' "$address" >&2
        fail "address-observation"
    fi
else
    printf '%s\n' "$address" >&2
    fail "address-query"
fi

mkdir -p /etc/dropbear 2>/dev/null
echo "QMU-NET-CONFIGURED $address"

# -F foreground (PID 1 stays alive + reaps) · -s no-password (key only) · -R auto host keys
# · -E log to console. If your dropbear is >= 2018.76 you may use ed25519 keys; older
# (e.g. bionic 2017.75) supports only ecdsa/rsa — use ECDSA host + client keys.
shopt -s execfail
exec dropbear -F -E -s -R -p 22
fail "dropbear-exec"
