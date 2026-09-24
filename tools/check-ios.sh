#!/usr/bin/env bash
# Build the local XCFramework and run the Swift package tests on an iOS simulator.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

if [[ $(uname -s) != Darwin || $(uname -m) != arm64 ]]; then
  echo "check-ios.sh requires Apple Silicon macOS for the arm64 simulator slice" >&2
  exit 1
fi
for tool in xcodebuild xcrun; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done
xcrun --sdk iphonesimulator --show-sdk-path >/dev/null

if [[ -n ${BHWI_IOS_DESTINATION:-} ]]; then
  destination=$BHWI_IOS_DESTINATION
else
  udid=$(xcrun simctl list devices available | awk -F '[()]' '/^[[:space:]]+iPhone/ { print $2; exit }')
  if [[ -z $udid ]]; then
    echo "no available iPhone simulator; set BHWI_IOS_DESTINATION" >&2
    exit 1
  fi
  destination="platform=iOS Simulator,id=$udid"
fi

bash ./tools/build-ios.sh

echo "==> XCTest ($destination)"
xcodebuild -scheme Bhwi -destination "$destination" test
