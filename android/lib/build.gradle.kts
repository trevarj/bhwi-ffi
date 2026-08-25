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
        named("test") {
            kotlin.srcDir("src/test/kotlin")
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

    testImplementation("junit:junit:4.13.2")
    testImplementation(kotlin("test"))
    // The `@aar` artifact above carries no desktop JNI dispatch library, so the JVM
    // replay tests need the plain jar.
    testImplementation("net.java.dev.jna:jna:5.19.0")
}

// JVM unit tests load the host cdylib built by tools/build-android.sh and replay the
// transcripts checked into fixtures/; both live outside the Gradle project.
tasks.withType<Test>().configureEach {
    // Declared as inputs so a rebuilt cdylib or an edited fixture invalidates a cached
    // test result; a system property alone would let a stale PASS survive both.
    inputs.file(rootDir.resolve("../target/release/libbhwi_ffi.so"))
        .withPropertyName("hostCdylib")
        .withPathSensitivity(PathSensitivity.NONE)
    inputs.dir(rootDir.resolve("../fixtures"))
        .withPropertyName("fixtures")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    systemProperty("jna.library.path", rootDir.resolve("../target/release").canonicalPath)
    systemProperty("bhwi.fixtures.dir", rootDir.resolve("../fixtures").canonicalPath)
    testLogging {
        events("passed", "skipped", "failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
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
