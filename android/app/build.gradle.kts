plugins {
    // AGP 9+ built-in Kotlin support replaces the org.jetbrains.kotlin.android plugin.
    id("com.android.application")
}

android {
    namespace = "eu.cisodiagonal.socmap"
    compileSdk = 37

    defaultConfig {
        applicationId = "eu.cisodiagonal.socmap"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

// Kotlin 2.x compilerOptions DSL (replaces the deprecated kotlinOptions block).
kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.19.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
}
