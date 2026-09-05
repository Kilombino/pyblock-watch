import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.kilombino.pyblockwatch"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.kilombino.pyblockwatch"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        // No ndk{} block and no abiFilters: this app ships ZERO native libraries,
        // so one APK runs on every ABI. See README-REPRODUCIBLE.md §1.
    }

    buildTypes {
        release {
            // Off for the same reason the upstream app keeps it off during beta —
            // but here it also removes a whole class of build nondeterminism, which
            // matters more than the ~1 MB it would save on an app this small.
            isMinifyEnabled = false
            isShrinkResources = false
            isDebuggable = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures { compose = true }

    packaging {
        resources.excludes += setOf("/META-INF/{AL2.0,LGPL2.1}")
    }
}

kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)

    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    // NOTE: there is deliberately no crypto dependency here — no BouncyCastle, no
    // bdk, no secp256k1 JNI. secp256k1, RIPEMD-160, Base58 and Bech32 all live in
    // app/src/main/java/.../crypto/ so the entire cryptographic path is source you
    // can read and rebuild. JSON comes from org.json, which is part of Android.

    testImplementation("junit:junit:4.13.2")
}
