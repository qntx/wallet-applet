plugins {
    java
    alias(libs.plugins.cyclonedx)
}

description = "qntx card applet (one CAP, package org.qntx.card)"

val jcKitDir = rootProject.layout.projectDirectory.dir("sdks/${libs.versions.javacard.sdk.get()}")
val targetSdk =
    libs.versions.javacard.target
        .get()

val antJavaCard: Configuration by configurations.creating

dependencies {
    antJavaCard(libs.ant.javacard)
    compileOnly(files(jcKitDir.file("lib/api_classic-$targetSdk.jar")))
}

tasks.compileJava {
    options.release = 8
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Xlint:-options", "-Werror"))
}

val packageAid = "F0716E747800"
val walletAid = "F0716E74780101"
val ndefAid = "F0716E74780201"
val capFile = layout.buildDirectory.file("cap/qntx-card.cap")

val cap by tasks.registering {
    group = "build"
    description = "Converts the applet package into qntx-card.cap with the JCDK converter."
    val sources = layout.projectDirectory.dir("src/main/java")
    val kit = jcKitDir.asFile
    val antClasspath = antJavaCard
    inputs.files(antClasspath).withPropertyName("antJavaCard")
    inputs.dir(sources).withPropertyName("sources")
    inputs.dir(jcKitDir).withPropertyName("jckit")
    outputs.file(capFile)
    dependsOn(tasks.compileJava)
    doLast {
        val out = capFile.get().asFile
        out.parentFile.mkdirs()
        check(kit.isDirectory) { "JavaCard SDK missing at $kit: run `git submodule update --init`" }
        CapBuild.convertCap(
            ant,
            antClasspath.asPath,
            kit,
            out,
            packageAid,
            "org.qntx.card",
            targetSdk,
            sources.asFile,
            listOf(
                "org.qntx.card.WalletApplet" to walletAid,
                "org.qntx.card.NdefApplet" to ndefAid,
            ),
        )
        CapBuild.normalizeCap(out)
    }
}

tasks.assemble { dependsOn(cap) }

tasks.cyclonedxDirectBom {
    projectType = org.cyclonedx.model.Component.Type.FIRMWARE
    componentName = "qntx-card"
    includeConfigs = listOf("antJavaCard", "compileClasspath")
    jsonOutput =
        layout.buildDirectory
            .file("reports/qntx-card.cdx.json")
            .get()
            .asFile
    xmlOutput.unsetConvention()
}
