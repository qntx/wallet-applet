plugins {
    java
    alias(libs.plugins.pitest)
}

description = "Simulator, vector and mutation tests of the qntx card applet"

val agent: Configuration by configurations.creating
val cap = project(":applet").layout.buildDirectory.file("cap/qntx-card.cap")
val apiClassicJar =
    rootProject.layout.projectDirectory.file(
        "sdks/${libs.versions.javacard.sdk.get()}/lib/api_classic-${libs.versions.javacard.target.get()}.jar",
    )
val vectorGen: SourceSet by sourceSets.creating {
    java.srcDir(rootProject.layout.projectDirectory.dir("spec/vectors/gen/java"))
}

dependencies {
    agent(project(path = ":sim", configuration = "agent"))
    testImplementation(project(":sim"))
    testCompileOnly(files(apiClassicJar))
    testImplementation(project(":applet"))
    testImplementation(project(":host"))
    testImplementation(libs.bouncycastle.prov)
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.jackson.jr)
    testRuntimeOnly(libs.junit.platform.launcher)
    "vectorGenImplementation"(libs.bouncycastle.prov)
}

tasks.test {
    useJUnitPlatform()
    dependsOn(":applet:cap")
    inputs.file(cap).withPropertyName("cap")
    inputs.files(agent).withPropertyName("agent")
    jvmArgumentProviders.add { listOf("-javaagent:${agent.singleFile.absolutePath}") }
    systemProperty("qntx.cap", cap.get().asFile.absolutePath)
    systemProperty("qntx.vectors", rootProject.file("spec/vectors").absolutePath)
    // heavy acceptance counts are settable from the daemon command line
    // (-Dqntx.differential=N …) so a quick local run needs no file edit
    for (name in listOf("qntx.differential", "qntx.modarith.rounds", "qntx.nonce.count")) {
        providers.systemProperty(name).orNull?.let { systemProperty(name, it) }
    }
    systemProperty(
        "qntx.reports",
        layout.buildDirectory
            .dir("reports")
            .get()
            .asFile.absolutePath,
    )
    testLogging {
        events("failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
    finalizedBy(memoryReport)
}

val memoryReport by tasks.registering {
    description = "Prints the simulator's transient-memory report of the installed applet."
    val report = layout.buildDirectory.file("reports/memory.txt")
    doLast {
        val file = report.get().asFile
        if (file.exists()) println(file.readText())
    }
}

val generateVectors by tasks.registering(JavaExec::class) {
    group = "verification"
    description = "Writes every vector file of spec/protocol.md section 18 with the Java generator."
    val out = layout.buildDirectory.dir("vectors/java")
    classpath = vectorGen.runtimeClasspath
    mainClass = "org.qntx.card.vectors.Generate"
    argumentProviders.add { listOf(out.get().asFile.absolutePath) }
    outputs.dir(out)
}

pitest {
    pitestVersion =
        libs.versions.pit.core
            .get()
    junit5PluginVersion =
        libs.versions.pit.junit5
            .get()
    targetClasses =
        listOf(
            "org.qntx.card.WalletApplet",
            "org.qntx.card.Session",
            "org.qntx.card.Identity",
            "org.qntx.card.Wallet",
            "org.qntx.card.Derivation",
            "org.qntx.card.State",
            "org.qntx.card.Ecdsa",
            "org.qntx.card.Bip340",
            "org.qntx.card.Ed25519",
            "org.qntx.card.ModArith",
            "org.qntx.card.Transfer",
        )
    targetTests = listOf("org.qntx.card.*")
    additionalMutableCodePaths =
        listOf(
            project(":applet")
                .layout.buildDirectory
                .dir("classes/java/main")
                .get()
                .asFile,
        )
    jvmArgs =
        provider {
            listOf(
                "-javaagent:${agent.singleFile.absolutePath}",
                "-Dqntx.cap=${cap.get().asFile.absolutePath}",
                "-Dqntx.vectors=${rootProject.file("spec/vectors").absolutePath}",
                "-Dqntx.reports=${layout.buildDirectory.dir("reports").get().asFile.absolutePath}",
                // small counts inside PIT JVMs: the covered paths are killed by the
                // vector and command suites; acceptance counts stay on the test task
                "-Dqntx.differential=25",
                "-Dqntx.modarith.rounds=200",
                "-Dqntx.nonce.count=25",
                "-Dqntx.fuzz=40",
                "-Dqntx.decompress.randoms=30",
            )
        }
    excludedTestClasses =
        listOf(
            // covered paths are killed by the vector and command suites; it would
            // multiply the run
            "SignDifferentialTest",
        )
    mutators = listOf("STRONGER")
    excludedMethods =
        listOf(
            // the multi-block loop is unreachable in the simulator (receiveBytes
            // returns the whole Lc in one shot); it exists for real-card chaining
            "*receiveAll",
            // pending() is a redundant member check behind beginDispatch, which runs the
            // same membership dispatch itself: a corrupt word gets the identical 6F00
            // from either layer, so its conditional mutants are equivalent there
            "*pending",
            // txDepth wraps getTransactionDepth solely so the depth gate can be armed;
            // its return mutants coincide with the read-back gate that follows
            "*txDepth",
            // countRange is the spec check-3 wording of c in {2,3}: the dispatch's
            // {160,176} IMPORT bound plus |payload| = 98 + 16c already force it, so
            // every never-branch mutant is equivalent — kept for check-order fidelity
            "*countRange",
            // seedOff's only mutant shifts the master's 64-byte window by one; a
            // shifted window still derives a valid BIP-32 master with overwhelming
            // probability, so no input distinguishes it
            "*seedOff",
            // slotOf runs only after memberSlot has thrown on self == found, so the
            // equality boundary mutant is unreachable; the direction mutants coincide
            // with the peer-slot writes asserted by the transfer tests
            "*slotOf",
        )
    avoidCallsTo =
        listOf(
            // Const.init forces install-time class initialisation, which runs once
            // per JVM and is unobservable to mutation tests since PIT reuses JVMs
            "org.qntx.card.Const",
        )
    mutationThreshold = 100
    timestampedReports = false
    outputFormats = listOf("HTML", "XML")
}

tasks.named("pitest") { dependsOn(":applet:cap", agent) }
