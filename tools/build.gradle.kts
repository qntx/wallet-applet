plugins {
    java
    application
}

description = "qntx-card: the batch provisioning CLI (architecture.md §11, protocol.md §14.3)"

dependencies {
    implementation(libs.picocli)
    // GlobalPlatformPro is the independent GP host implementation the production
    // procedure rides on; apdu4j supplies BIBO transports.
    implementation(libs.gppro)
    implementation(libs.apdu4j.core)
    implementation(libs.apdu4j.pcsc)
    implementation(project(":host"))
    implementation(libs.bouncycastle.prov)
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
    runtimeOnly(libs.slf4j.nop)
    testRuntimeOnly(libs.slf4j.simple)
}

application {
    mainClass = "org.qntx.card.tools.Main"
    applicationName = "qntx-card"
}

distributions {
    main {
        contents {
            // licence trail at the distribution root, next to bin/ and lib/
            from(rootProject.file("LICENSE"))
            from(rootProject.file("LICENSES")) { into("LICENSES") }
        }
    }
}

tasks.test {
    useJUnitPlatform()
    dependsOn(":applet:cap", ":sim:shadowJar")
    systemProperty(
        "qntx.simJar",
        project(":sim")
            .layout.buildDirectory
            .file("libs/card-sim.jar")
            .get()
            .asFile.absolutePath,
    )
    systemProperty(
        "qntx.cap",
        project(":applet")
            .layout.buildDirectory
            .file("cap/qntx-card.cap")
            .get()
            .asFile.absolutePath,
    )
    systemProperty("qntx.vectors", rootProject.file("spec/vectors").absolutePath)
}
