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
        // `:sample` consumes the published AAR, not the project, so the consumption path
        // is exercised exactly as an app would. Repositories must be declared here
        // because of FAIL_ON_PROJECT_REPOS above.
        mavenLocal()
    }
}

rootProject.name = "bhwi-ffi-android"

include(":lib")
include(":sample")
