// Root build = the `kemseed` library (single-project Gradle build).
// Kotlin Multiplatform + Android library (versions pinned in gradle/libs.versions.toml).
// Runtime deps policy: ADR-0001 (zero external deps) — relaxed ONLY for the kompact 0.1.6
// runtime (kotlin-stdlib only, Unlicense) by ADR-0003. kompact-ksp 0.1.6 (compile-time-only;
// kotlinpoet-jvm, NOT on the device runtime; Unlicense — see docs/adr/0003) is wired for KSP
// codegen of @KommutModel expect value classes.
//
// kompact-ksp 0.1.6 (KSP 2.3.12, paired w/ Kotlin 2.4.20) fixes vs 0.1.2:
//  (A) KSP-2.x service-file registration — the processor now LOADS + PARSES correctly
//      (`loaded provider(s): [ch.trancee.kompact.ksp.KompactSymbolProcessorProvider]`) and emits
// into the correct
//      platform trees (no FileAlreadyExistsException, no KMP expect/actual mis-routing).
//  (B) See (A).
// The generator (0.1.6; defect #3 fixed via upstream PR #48 in 0.1.5; defect #4 fixed via
// upstream PR #51 in 0.1.6): `ValueClassGenerator.buildActual` now emits `val raw` on the
// constructor + `public actual companion object` — so the `@JvmInline value class
// AdPduHeader(raw: ByteArray)` compiles. Codegen is ON -> the generator emits the platform
// actuals per-KSP-task (see the `kompact.generate=<mode>` mode routing below); the hand-written
// platform actuals are deleted. See docs/adr/0003 §v1.5.

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.library)
    alias(libs.plugins.ksp)
    alias(libs.plugins.spotless)
}

spotless {
    // Q1 repo gate (Constitution Q1 + AGENTS spotless skill): ktfmt-formatted Kotlin.
    // Incremental rollout — ratchet only files changed since the local `main` base
    // (no `origin` remote is configured). Never ratchetFrom HEAD. Keeps the gate
    // scoped to the diff instead of a repo-wide reformat on a single-project KMP lib.
    // kotlinlangStyle = Kotlin-official preset (4-space, 120 col) pinned for both .kt
    // and .kst so source and build scripts format identically (reproducible, E1).
    ratchetFrom = "main"
    kotlin {
        ktfmt(libs.versions.ktfmt.get()).kotlinlangStyle()
    }
    kotlinGradle {
        ktfmt(libs.versions.ktfmt.get()).kotlinlangStyle()
    }
}

dependencies {
    // kompact-ksp 0.1.6: registered under the KSP-2.x service path; discoverable by
    // KSP 2.3.12 (the KSP paired with Kotlin 2.4.20). Verified it loads + parses
    // @KommutModel (`processing AdPduHeader (3 fields, 8 bits, 1 bytes)`). Bound via the
    // `kspAndroid` aggregate config (eager dep-handler accessor). @KommutModel codegen is ON.
    kspAndroid(libs.kompactKsp)
}

// `kspIos` config is lazy: KGP 2.4 emits no `kspIos(...)` Kotlin-DSL accessor, and the
// config is created by the KMP ios target after the root `dependencies{}` block — so
// `add("kspIos", ...)` there throws "Configuration with name 'kspIos' not found".
// Defer to afterEvaluate. The generator emits the ios actual (ios mode), routed per-task
// via the mode arg below. A raw `add("kspIos", ...)` only lands on iosMain's *source-set*
// config; the `kspKotlinIos` task reads its own `kspKotlinIosProcessorClasspath`, so we
// bind the processor to that task classpath too (kommut-ksp 0.1.6, defects #3+#4 fixed).
afterEvaluate {
    dependencies {
        add("kspIos", libs.kompactKsp)
        add("kspKotlinIosProcessorClasspath", libs.kompactKsp)
    }
}

// Per-KSP-task mode arg for the generator (0.1.6, defects #3+#4 fixed). The processor reads
// the mode from the `kompact.generate=<mode>` option; default mode "all" emits the expect + BOTH
// actuals into one source set -> duplicates, so route per platform task:
//   kspAndroidMain -> `kompact.generate=jvm` -> @JvmInline actual -> androidMain
//   kspKotlinIos   -> `kompact.generate=ios` -> plain actual      -> iosMain
// kspMetadata (common) is left unarged -> the processor does not run there; the @KommutModel
// expect in commonMain is the schema (not regenerated; the processor emits only actuals per mode).
afterEvaluate {
    tasks.withType<com.google.devtools.ksp.gradle.KspAATask>().configureEach {
        val mode =
            when (name) {
                "kspAndroidMain" -> "jvm"
                "kspKotlinIos" -> "ios"
                else -> return@configureEach
            }
        commandLineArgumentProviders.add(
            object : org.gradle.process.CommandLineArgumentProvider {
                override fun asArguments(): Iterable<String> = listOf("kompact.generate=" + mode)
            }
        )
    }
}

kotlin {
    android {
        namespace = "ch.trancee.kemseed"
        compileSdk = libs.versions.compileSdk.get().toInt() // 36 (android-36; build-tools 36.0.0)
        minSdk = libs.versions.minSdk.get().toInt() // 21 (ADR-0001)
        withHostTest {} // host JVM unit tests (new Android-KMP plugin; task: testAndroidHostTest)
        // Align bytecode target with kompact 0.1.6's published runtime (JVM_21), Kompact.kt
        // JVM-side ABI validation. Keeps variant matching happy for the kompact-android AAR.
        compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21) }
    }
    // iOS device-only (arm64). Using iosArm64("ios") names the target `ios`:
    // source set `iosMain`; KMP compile task `compileKotlinIos` (not …IosMain).
    // No iOS simulator target (iosSimulatorArm64 / iosX64) — BLE does not
    // work in the iOS simulator.
    iosArm64("ios")
    sourceSets {
        val commonMain by getting {
            dependencies {
                // kompact runtime: stdlib-only, consumed as `ch.trancee.kompact:kompact` KMP.
                // Provides KompactWriter/KompactRuntime/ScalarType/KompactFraming for deterministic
                // cross-platform bit-packing of the AD-PDU (§1.6 — frozen nonce scheme).
                implementation(libs.kompact)
            }
            // AdPduHeader is a model-annotation expect value-class shape (ADR-0003 §Adoption), so
            // -Xexpect-actual-classes is required to consume the published expect/actual value
            // classes (e.g. ScalarType) and kemseed's own expect. The generator (0.1.6, defects
            // #3+#4
            // fixed) emits the platform actuals (jvm/ios via the per-task kompact.generate mode arg
            // below); @KommutModel is ON on the expect.
            compilerOptions { freeCompilerArgs.addAll("-Xexpect-actual-classes") }
        }
        val androidMain by getting {
            // -Xexpect-actual-classes: the generator emits the @JvmInline actual here
            // (AdPduHeaderGenJvm.kt); the hand-written actual is deleted.
            compilerOptions { freeCompilerArgs.addAll("-Xexpect-actual-classes") }
        }
        val iosMain by getting {
            compilerOptions { freeCompilerArgs.addAll("-Xexpect-actual-classes") }
        }
        val commonTest by getting {
            dependencies { implementation(kotlin("test")) }
        }
    }
}
