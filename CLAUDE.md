# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Simple Security Checks is an Android app that performs various device security checks, including root detection. It is currently in early development with root detection implemented.

- **Package**: `com.khasmek.simplesecuritychecks`
- **Min SDK**: 24, **Target/Compile SDK**: 36
- **Language**: Kotlin with Jetpack Compose (no XML layouts)
- **Build system**: Gradle 9.1 with Kotlin DSL and version catalogs (`gradle/libs.versions.toml`)
- **AGP**: 9.0.0, **Kotlin**: 2.0.21

## Build Commands

```bash
./gradlew assembleDebug          # Build debug APK
./gradlew assembleRelease        # Build release APK
./gradlew test                   # Run unit tests
./gradlew connectedAndroidTest   # Run instrumented tests (requires device/emulator)
./gradlew testDebugUnitTest      # Run only debug unit tests
```

## Architecture

Single-module app (`app/`) with one activity (`MainActivity`). UI is built entirely with Jetpack Compose and Material 3. The theme is defined in `app/src/main/java/com/khasmek/simplesecuritychecks/ui/theme/`.

Source layout follows standard Android conventions:
- `app/src/main/` — application code and resources
- `app/src/test/` — local JVM unit tests (JUnit 4)
- `app/src/androidTest/` — instrumented tests (Espresso + Compose UI testing)
