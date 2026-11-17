# Root Manager 0.1.0

Standalone Android diagnostic APK for observing a temporary root session managed externally by DirtyFrag + ReSukiSU.

## Scope
- Read-only device, kernel, ABI, Android and SELinux observations.
- Root status check using `su -c id`.
- Timestamped diagnostic report saved inside the app-specific external files directory.
- Copy report to clipboard.

## Safety and limitations
- The app does not install, launch, or modify DirtyFrag or ReSukiSU.
- It does not exploit vulnerabilities, change SELinux, alter boot state, hide root, or bypass app security checks.
- The first root check may trigger a ReSukiSU authorization prompt. Grant access only if you trust this app.
- KMI is displayed as an estimate from the kernel release string, not as authoritative detection.
- Root status is `UNKNOWN` if the `su` command fails or times out; a failed check is not treated as proof that the device is unrooted.

## Build
Open this folder in Android Studio (AGP 8.7.3, JDK 17), or run:
`gradle assembleDebug`

GitHub Actions builds a debug APK on push to `main` or manual workflow dispatch. Artifact: `RootManager-debug`.

Package: `id.daniel.rootmanager`
Version: `0.1.0` (versionCode 1)
