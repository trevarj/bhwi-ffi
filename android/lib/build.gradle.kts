plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("maven-publish")
}

android {
    namespace = "com.wizardsardine.bhwi"
    compileSdk = 35
    // Pinned: the SDK in the devshell is read-only, so AGP must not try to fetch
    // a different build-tools revision.
    buildToolsVersion = "35.0.0"

    defaultConfig {
        minSdk = 28
        consumerProguardFiles("consumer-rules.pro")
    }

    sourceSets {
        named("main") {
            // Populated by tools/build-android.sh, both untracked.
            kotlin.srcDir("src/main/kotlin")
            jniLibs.srcDir("src/main/jniLibs")
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

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

dependencies {
    // Exactly what the generated bindings import.
    implementation("net.java.dev.jna:jna:5.19.0@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
}

publishing {
    publications {
        register<MavenPublication>("release") {
            groupId = "com.wizardsardine"
            artifactId = "bhwi-ffi-android"
            version = "0.1.0-SNAPSHOT"
            afterEvaluate { from(components["release"]) }
        }
    }
}
