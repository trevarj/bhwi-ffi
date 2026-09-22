#!/usr/bin/env bash
# Boot a headless API 34 x86_64 emulator and run the sample's instrumentation tests.
#
# The emulator lives in a separate devshell (`nix develop .#emulator`) so the default
# shell stays small; `adb` is present in both and they share the one adb server.
#
# NOTE: this host has no /dev/kvm, so the emulator runs fully emulated (`-accel off`).
# Boot then takes tens of minutes and may not finish at all. The JVM replay suite
# (`tools/check.sh`) is the real gate; this script is the on-device confirmation.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

avd=${BHWI_AVD:-bhwi-api34-x86_64}
image=${BHWI_SYSTEM_IMAGE:-system-images;android-34;default;x86_64}
# Fully emulated boot is slow; give it half an hour by default.
boot_timeout=${BHWI_BOOT_TIMEOUT:-1800}
accel=${BHWI_ACCEL:-off}
log=${BHWI_EMULATOR_LOG:-$root/target/emulator.log}

emu() { nix develop .#emulator -c "$@"; }

mkdir -p "$(dirname "$log")"

echo "==> avd"
if ! emu avdmanager list avd -c | grep -qx "$avd"; then
  echo "creating $avd from $image"
  echo no | emu avdmanager create avd -n "$avd" -k "$image" --force
fi

echo "==> boot (accel=$accel, timeout=${boot_timeout}s, log=$log)"
emu emulator -avd "$avd" -accel "$accel" -no-window -no-audio -no-boot-anim \
  -no-snapshot -gpu swiftshader_indirect >"$log" 2>&1 &
emulator_pid=$!

cleanup() {
  # Ask nicely first; the emulator flushes its disk image on `emu kill`.
  emu adb -s emulator-5554 emu kill >/dev/null 2>&1 || true
  kill "$emulator_pid" >/dev/null 2>&1 || true
  wait "$emulator_pid" 2>/dev/null || true
}
trap cleanup EXIT

deadline=$((SECONDS + boot_timeout))
until [ "$(emu adb -s emulator-5554 shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; do
  if ! kill -0 "$emulator_pid" 2>/dev/null; then
    echo "emulator exited before boot; see $log" >&2
    tail -20 "$log" >&2
    exit 1
  fi
  if [ "$SECONDS" -ge "$deadline" ]; then
    echo "emulator did not boot within ${boot_timeout}s; see $log" >&2
    tail -20 "$log" >&2
    exit 1
  fi
  sleep 10
done
emu adb -s emulator-5554 wait-for-device

# `sys.boot_completed` fires before the device answers property/package queries
# reliably, and AGP skips a device whose API level it cannot read ("Unknown API
# Level"). Wait until both answer.
until [ -n "$(emu adb -s emulator-5554 shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r')" ] &&
  emu adb -s emulator-5554 shell pm path android >/dev/null 2>&1; do
  if [ "$SECONDS" -ge "$deadline" ]; then
    echo "emulator booted but never settled; see $log" >&2
    exit 1
  fi
  sleep 10
done

echo "==> connectedDebugAndroidTest"
# Pin the target: `connectedAndroidTest` otherwise installs on every attached device,
# including any phone the developer happens to have plugged in.
export ANDROID_SERIAL=emulator-5554
# Default shell: it owns the build SDK, the NDK and the Gradle configuration.
(cd android && ./gradlew --no-daemon :sample:connectedDebugAndroidTest)

echo "==> instrumentation passed"
