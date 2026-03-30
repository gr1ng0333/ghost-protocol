# Release packaging

This directory keeps release templates, example configuration, and packaging material.

Generated binaries (`ghost-client`, `ghost-server`, `.exe`, `.apk`, `.aar`) are intentionally kept out of git so the repository stays reviewable and source-focused. Build artifacts should be produced locally or in CI from the source tree.

Typical build paths:

- Linux client/server: `go build ./cmd/...`
- Android AAR: `cd mobile && ./build.sh`
- Android APK: `cd android && ./gradlew assembleDebug`
