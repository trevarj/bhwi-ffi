#!/usr/bin/env bash
# Build the local XCFramework and run the Swift package tests on an iOS simulator.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

./tools/build-ios.sh

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

echo "==> XCTest ($destination)"
xcodebuild -scheme Bhwi -destination "$destination" test
