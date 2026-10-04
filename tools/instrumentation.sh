#!/usr/bin/env bash
# Use ANDROID_SERIAL's running device, or own a headless API 34 x86_64 emulator.
#
# The emulator lives in a separate devshell (`nix develop .#emulator`) so the default
# shell stays small; `adb` is present in both and they share the one adb server.
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

deadline=$((SECONDS + boot_timeout))
if [ "${ANDROID_SERIAL+x}" = x ]; then
  serial=$ANDROID_SERIAL
  if [ -z "$serial" ] || [ "$(adb -s "$serial" get-state 2>/dev/null)" != device ]; then
    echo "ANDROID_SERIAL must identify an already running, authorized device" >&2
    exit 1
  fi
  echo "==> using existing device $serial (no emulator lifecycle changes)"
else
  serial=emulator-5554
  if adb devices | grep -q "^${serial}[[:space:]]"; then
    echo "$serial is already present; set ANDROID_SERIAL to use it without taking ownership" >&2
    exit 1
  fi
  mkdir -p "$(dirname "$log")"

  echo "==> avd"
  if ! emu avdmanager list avd -c | grep -qx "$avd"; then
    echo "creating $avd from $image"
    echo no | emu avdmanager create avd -n "$avd" -k "$image" --force
  fi

  echo "==> boot (accel=$accel, timeout=${boot_timeout}s, log=$log)"
  emu emulator -avd "$avd" -port 5554 -accel "$accel" -no-window -no-audio -no-boot-anim \
    -no-snapshot -gpu swiftshader_indirect >"$log" 2>&1 &
  emulator_pid=$!

  cleanup() {
    adb -s "$serial" emu kill >/dev/null 2>&1 || true
    kill "$emulator_pid" >/dev/null 2>&1 || true
    wait "$emulator_pid" 2>/dev/null || true
  }
  trap cleanup EXIT
fi
export ANDROID_SERIAL=$serial

until [ "$(adb -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; do
  if [ -n "${emulator_pid:-}" ] && ! kill -0 "$emulator_pid" 2>/dev/null; then
    echo "emulator exited before boot; see $log" >&2
    tail -20 "$log" >&2
    exit 1
  fi
  if [ "$SECONDS" -ge "$deadline" ]; then
    echo "$serial did not become ready within ${boot_timeout}s" >&2
    exit 1
  fi
  sleep 10
done

# `sys.boot_completed` fires before the device answers property/package queries
# reliably, and AGP skips a device whose API level it cannot read ("Unknown API
# Level"). Wait until both answer.
until [ -n "$(adb -s "$serial" shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r')" ] &&
  adb -s "$serial" shell pm path android >/dev/null 2>&1; do
  if [ "$SECONDS" -ge "$deadline" ]; then
    echo "$serial booted but never settled" >&2
    exit 1
  fi
  sleep 10
done

echo "==> connectedDebugAndroidTest"
# Pin the target: `connectedAndroidTest` otherwise installs on every attached device,
# including any phone the developer happens to have plugged in.
# Default shell: it owns the build SDK, the NDK and the Gradle configuration.
(cd android && bash ./gradlew --no-daemon "$@" :sample:connectedDebugAndroidTest)

echo "==> instrumentation passed"
