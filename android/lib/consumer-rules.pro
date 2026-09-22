# JNA reaches the generated interfaces and structures reflectively.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keep class uniffi.bhwi_ffi.** { *; }
