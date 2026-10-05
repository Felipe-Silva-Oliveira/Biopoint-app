[app]
title = Bio Point
package.name = biopoint
package.domain = org.test
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,txt
version = 0.1
requirements = python3,kivy

# Configurações de API e o caminho manual do NDK:
android.api = 33
android.minapi = 21
android.ndk = 25b
android.ndk_path = /root/.buildozer/android/platform/android-ndk-r25b
android.sdk_path = 

orientation = portrait
fullscreen = 1
android.archs = arm64-v8a
android.allow_backup = True

[buildozer]
log_level = 2
warn_on_root = 0
