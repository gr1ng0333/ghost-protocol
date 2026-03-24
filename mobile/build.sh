#!/usr/bin/env bash
# Build Ghost mobile AAR for Android using gomobile.
#
# Prerequisites:
#   go install golang.org/x/mobile/cmd/gomobile@latest
#   gomobile init
#   ANDROID_HOME must be set (Android SDK path)
#   NDK must be installed (via sdkmanager "ndk;26.1.10909125" or similar)
#
# Usage:
#   ./build.sh              # builds ghost.aar + ghost-sources.jar
#   ./build.sh -o out.aar   # custom output path

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_ROOT}"

if ! command -v gomobile &> /dev/null; then
    echo "ERROR: gomobile not found. Install with:"
    echo "  go install golang.org/x/mobile/cmd/gomobile@latest"
    exit 1
fi

if [ -z "${ANDROID_HOME:-}" ]; then
    echo "ERROR: ANDROID_HOME not set"
    exit 1
fi

OUTPUT="${1:--o mobile/ghost.aar}"

echo "Building Ghost mobile AAR..."
gomobile bind \
    -target=android/arm64 \
    -androidapi 24 \
    -ldflags="-s -w" \
    ${OUTPUT} \
    ghost/mobile

echo "Done: ghost.aar built successfully"
