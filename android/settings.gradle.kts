pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // The sample resolves this artifact only from the publication repository.
        // Gradle's mavenLocal honors -Dmaven.repo.local; otherwise local dev uses ~/.m2.
        exclusiveContent {
            forRepository { mavenLocal() }
            filter { includeModule("com.wizardsardine", "bhwi-ffi-android") }
        }
    }
}

rootProject.name = "bhwi-ffi-android"

include(":lib")
include(":sample")
