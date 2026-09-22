plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.wizardsardine.bhwi.sample"
    compileSdk = 35
    // Pinned for the same reason as in :lib — the devshell SDK is read-only.
    buildToolsVersion = "35.0.0"

    defaultConfig {
        applicationId = "com.wizardsardine.bhwi.sample"
        minSdk = 28
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    sourceSets {
        named("main") { kotlin.srcDir("src/main/kotlin") }
        named("androidTest") {
            kotlin.srcDir("src/androidTest/kotlin")
            // The replay transcripts ship in the test APK straight from the repo, so the
            // instrumentation test and the JVM test read byte-identical fixtures.
            assets.srcDir(rootDir.resolve("../fixtures"))
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlin {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        }
    }
}

dependencies {
    // Deliberately the published artifact from mavenLocal, not project(":lib"): this is
    // what proves the consumption path an app would take.
    implementation("com.wizardsardine:bhwi-ffi-android:0.1.0-SNAPSHOT")

    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
}
