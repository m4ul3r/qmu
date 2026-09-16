#!/bin/bash
# TEMPLATE: dependency-inspection init (PID 1). QMU-BOOT-OK proves only script entry;
# QMU-BOOT-DONE means ldd produced nonempty output with no unresolved dependencies,
# not functional loading or vendor-service readiness. Read serial output with `qmu log`.
#   --cmdline 'console=ttyAMA0 root=/dev/vda rw init=/qmu-probe-init.sh'   # ttyS0 on x86
# Edit the >>> EDIT <<< lines for your firmware's target binaries.
export PATH=/bin:/sbin:/usr/bin:/usr/sbin

mount -t proc     proc /proc 2>/dev/null
mount -t sysfs    sys  /sys  2>/dev/null
mount -t devtmpfs dev  /dev  2>/dev/null

echo "=================== QMU-BOOT-OK ==================="
uname -a
sed -n '1,4p' /etc/os-release 2>/dev/null

fail() {
    echo "QMU-PROBE-FAILED: $*" >&2
    while :; do sleep 5; done
}

# >>> EDIT: replace this synthetic example with an identified firmware lib/binary <<<
echo "--- ldd a target lib ---"
if dependencies=$(LC_ALL=C LD_LIBRARY_PATH=/usr/lib64:/usr/lib ldd /usr/lib/libexample.so 2>&1); then
    printf '%s\n' "$dependencies"
else
    status=$?
    printf '%s\n' "$dependencies"
    fail "ldd exited $status"
fi
if [[ "$dependencies" =~ =\>[[:space:]]+not[[:space:]]found ]]; then
    fail "unresolved dependencies"
fi
if [[ ! "$dependencies" =~ [^[:space:]] ]]; then
    fail "empty dependency evidence"
fi

echo "=================== QMU-BOOT-DONE ==================="
sync
poweroff -f 2>/dev/null || halt -f 2>/dev/null || { echo o >/proc/sysrq-trigger 2>/dev/null; }
while :; do sleep 5; done
