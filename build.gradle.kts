// Root build = the `kemseed` library (single-project Gradle build).
// Kotlin Multiplatform + Android library (versions pinned in gradle/libs.versions.toml).
// Zero external runtime dependencies by policy (see docs/adr/0001-stack-and-dependency-constraints.md).

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.library)
}

kotlin {
    android {
        namespace = "ch.trancee.kemseed"
        compileSdk = libs.versions.compileSdk.get().toInt() // 36 (android-36; build-tools 36.0.0)
        minSdk = libs.versions.minSdk.get().toInt()        // 21 (ADR-0001)
        withHostTest { }                                     // host JVM unit tests (new Android-KMP plugin; task: testAndroidHostTest)
    }
    // iOS device-only (arm64). Using iosArm64("ios") names the target `ios`:
    // source set `iosMain`, task `compileKotlinIosMain`. No iOS simulator target
    // (iosSimulatorArm64 / iosX64) — BLE does not work in the iOS simulator.
    iosArm64("ios")
    sourceSets {
        val commonMain by getting
        val androidMain by getting
        val iosMain by getting
        val commonTest by getting {
            dependencies { implementation(kotlin("test")) }
        }
    }
}
