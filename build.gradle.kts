plugins {
    alias(libs.plugins.spotless)
    alias(libs.plugins.cyclonedx)
}

val gjfVersion =
    libs.versions.google.java.format
        .get()
val ktlintVersion = libs.versions.ktlint.get()

fun spdxHeader(license: String) = "// SPDX-FileCopyrightText: 2026 QuantX\n// SPDX-License-Identifier: $license\n"

allprojects {
    group = "org.qntx.card"
}

spotless {
    java {
        target("spec/vectors/gen/java/**/*.java")
        googleJavaFormat(gjfVersion).aosp()
        licenseHeader(spdxHeader("MIT OR Apache-2.0"))
    }
    kotlin {
        target("buildSrc/src/**/*.kt")
        ktlint(ktlintVersion)
        licenseHeader(spdxHeader("AGPL-3.0-or-later"))
    }
    kotlinGradle {
        target("*.gradle.kts", "buildSrc/*.gradle.kts")
        ktlint(ktlintVersion)
    }
}

// spotless#2850: a clean in the same invocation clears the daemon-wide formatter
// classloader cache once per build; a spotless task running after it hits a closed
// jar, which cascades into NoClassDefFoundError lint errors. Order every spotless
// task after every clean in every project — mustRunAfter never forces a clean.
allprojects {
    val allCleans = rootProject.allprojects.map { p -> p.tasks.matching { it.name == "clean" } }
    tasks.matching { it.name.startsWith("spotless") }.configureEach {
        mustRunAfter(allCleans)
    }
}

subprojects {
    apply(plugin = "com.diffplug.spotless")

    extensions.configure<com.diffplug.gradle.spotless.SpotlessExtension> {
        java {
            target("src/**/*.java")
            googleJavaFormat(gjfVersion).aosp()
            removeUnusedImports()
            licenseHeader(spdxHeader("AGPL-3.0-or-later"))
        }
        kotlinGradle {
            target("*.gradle.kts")
            ktlint(ktlintVersion)
        }
    }

    plugins.withId("java") {
        extensions.configure<JavaPluginExtension> {
            toolchain.languageVersion =
                JavaLanguageVersion.of(
                    libs.versions.jdk
                        .get()
                        .toInt(),
                )
        }
        tasks.withType<JavaCompile>().configureEach {
            options.encoding = "UTF-8"
        }
        tasks.withType<AbstractArchiveTask>().configureEach {
            isPreserveFileTimestamps = false
            isReproducibleFileOrder = true
        }
    }
}

// Release distributables (architecture §12).

// The 14 vector files of protocol.md §18 by name: the zip must fail rather than ship a short
// set, so a glob alone is not enough.
val vectorFiles =
    listOf(
        "access.json",
        "apdu.json",
        "bip340.json",
        "cert.json",
        "derivation.json",
        "ecdsa.json",
        "ed25519.json",
        "kdf.json",
        "ndef.json",
        "record.json",
        "session.json",
        "transfer.json",
        "verify-sequence.json",
        "wrap.json",
    )

val vectorsZip by tasks.registering(Zip::class) {
    group = "distribution"
    description = "spec/vectors plus its MIT/Apache-2.0 licenses as build/dist/vectors.zip."
    // staged under build/vectors; the `dist` task copies it into build/dist with the rest
    destinationDirectory.set(layout.buildDirectory.dir("vectors"))
    archiveFileName.set("vectors.zip")
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
    doFirst {
        for (f in vectorFiles) {
            check(file("spec/vectors/$f").isFile) { "spec/vectors/$f missing (protocol §18)" }
        }
    }
    into("spec/vectors") {
        from("spec/vectors") { include(*(vectorFiles + "README.md").toTypedArray()) }
    }
    into("LICENSES") {
        from("LICENSES") { include("MIT.txt", "Apache-2.0.txt") }
    }
}

// One aggregate SBOM over every released component (CAP, card-sim.jar, tools). Only the
// runtimeClasspath of each project is scanned — released software carries no test-scope or
// build-tool dependency — which also keeps the output deterministic: the plugin's
// cdx:maven:package:test flag otherwise flips run to run. The plugin still writes a fresh
// metadata.timestamp (no option to disable); the random serialNumber is configured off.
subprojects {
    tasks.withType<org.cyclonedx.gradle.CyclonedxDirectTask>().configureEach {
        includeConfigs.set(listOf("runtimeClasspath"))
    }
}
tasks.cyclonedxBom {
    includeBomSerialNumber.set(false)
    jsonOutput.set(layout.buildDirectory.file("reports/qntx-card.cdx.json"))
    xmlOutput.unsetConvention()
}

val dist by tasks.registering {
    group = "distribution"
    description = "Copies every release artifact into build/dist and writes SHA256SUMS."
    val out = layout.buildDirectory.dir("dist")
    val artifacts =
        mapOf(
            "qntx-card.cap" to project(":applet").layout.buildDirectory.file("cap/qntx-card.cap"),
            "card-sim.jar" to project(":sim").layout.buildDirectory.file("libs/card-sim.jar"),
            "vectors.zip" to vectorsZip.flatMap { it.archiveFile },
            "qntx-card-${project.version}.zip" to
                project(":tools").layout.buildDirectory.file("distributions/qntx-card-${project.version}.zip"),
            "qntx-card.cdx.json" to
                tasks.cyclonedxBom.flatMap { it.jsonOutput },
        )
    inputs.files(artifacts.values)
    outputs.dir(out)
    dependsOn(":applet:cap", ":sim:shadowJar", ":tools:distZip", vectorsZip, tasks.cyclonedxBom)
    doLast {
        val dir = out.get().asFile
        dir.mkdirs()
        dir.listFiles()?.forEach { it.delete() }
        for ((name, src) in artifacts) {
            src.get().asFile.copyTo(File(dir, name), overwrite = true)
        }
        val sums =
            dir
                .listFiles()!!
                .filter { it.isFile && it.name != "SHA256SUMS" }
                .sortedBy { it.name }
                .joinToString("\n", postfix = "\n") { sha256(it) + "  " + it.name }
        File(dir, "SHA256SUMS").writeText(sums)
    }
}

fun sha256(file: File): String {
    val digest = java.security.MessageDigest.getInstance("SHA-256")
    file.inputStream().use { input ->
        val buf = ByteArray(1 shl 16)
        var n: Int
        while (input.read(buf).also { n = it } != -1) {
            digest.update(buf, 0, n)
        }
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}
