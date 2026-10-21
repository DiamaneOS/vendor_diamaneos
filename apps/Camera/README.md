# Camera prebuilt

Presigned Camera built from the DiamaneOS Camera source. The APK and its matching APK signature scheme v4 sidecar retain their signatures when included in the OS.

Source revisions, artifact hashes and the APK certificate digest are recorded in [provenance.json](provenance.json).

The Camera installs its CameraProcessor app (`prebuilt/processor-release.apk`
and its idsig, module `CameraProcessor`), built from the `processor` module of
the same source and signed with the Camera key. provenance.json records it
under `processor`.
