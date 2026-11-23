plugins {
    java
    alias(libs.plugins.pitest)
}

description = "Simulator, vector and mutation tests of the qntx card applet"

val agent: Configuration by configurations.creating
val antJavaCard: Configuration by configurations.creating
val cap = project(":applet").layout.buildDirectory.file("cap/qntx-card.cap")
val jcKitDir = rootProject.layout.projectDirectory.dir("sdks/${libs.versions.javacard.sdk.get()}")
val apiClassicJar =
    jcKitDir.file("lib/api_classic-${libs.versions.javacard.target.get()}.jar")
val vectorGen: SourceSet by sourceSets.creating {
    java.srcDir(rootProject.layout.projectDirectory.dir("spec/vectors/gen/java"))
}
val admission: SourceSet by sourceSets.creating {
    java.srcDir("src/admission/java")
}
val realCard: SourceSet by sourceSets.creating {
    java.srcDir("src/realCard/java")
}

dependencies {
    agent(project(path = ":sim", configuration = "agent"))
    antJavaCard(libs.ant.javacard)
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
    "admissionCompileOnly"(files(apiClassicJar))
    "realCardImplementation"(project(":host"))
    "realCardImplementation"(project(":sim"))
    "realCardImplementation"(project(":applet"))
    "realCardImplementation"(libs.bouncycastle.prov)
    "realCardImplementation"(platform(libs.junit.bom))
    "realCardImplementation"(libs.junit.jupiter)
    "realCardRuntimeOnly"(libs.junit.platform.launcher)
    "realCardImplementation"(admission.output)
    "realCardCompileOnly"(files(apiClassicJar))
}

tasks.named<JavaCompile>("compileAdmissionJava") {
    options.release = 8
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Xlint:-options", "-Werror"))
}

val admissionCapFile = layout.buildDirectory.file("cap/admission.cap")

/**
 * Test-only admission CAP of the real-card suite (architecture §10): package {@code F0716E7478FF}
 * with the probe applets {@code F0716E7478FF01} and {@code F0716E7478FF02}. Never part of a release
 * artifact.
 */
val admissionCap by tasks.registering {
    group = "build"
    description = "Converts the admission probe package into tests/build/cap/admission.cap."
    val sources = layout.projectDirectory.dir("src/admission/java")
    val kit = jcKitDir.asFile
    val antClasspath = antJavaCard
    inputs.files(antClasspath).withPropertyName("antJavaCard")
    inputs.dir(sources).withPropertyName("sources")
    inputs.dir(jcKitDir).withPropertyName("jckit")
    outputs.file(admissionCapFile)
    dependsOn("compileAdmissionJava")
    doLast {
        val out = admissionCapFile.get().asFile
        out.parentFile.mkdirs()
        check(kit.isDirectory) { "JavaCard SDK missing at $kit: run `git submodule update --init`" }
        CapBuild.convertCap(
            ant,
            antClasspath.asPath,
            kit,
            out,
            "F0716E7478FF",
            "org.qntx.card.admission",
            libs.versions.javacard.target
                .get(),
            sources.asFile,
            listOf(
                "org.qntx.card.admission.Probe" to "F0716E7478FF01",
                "org.qntx.card.admission.Probe2" to "F0716E7478FF02",
            ),
        )
        CapBuild.normalizeCap(out)
    }
}

// The real-card suite of architecture §10: never in CI and never run by `check`. Without
// -PrealCard=<reader> every test is skipped as "not run"; -PrealCard=sim runs the suite
// in-process on the simulator as a self-check, not hardware evidence.
tasks.register<Test>("realCard") {
    group = "verification"
    description = "Runs the architecture §10 real-card suite; needs -PrealCard=<reader> or sim."
    testClassesDirs = realCard.output.classesDirs
    classpath = realCard.runtimeClasspath
    useJUnitPlatform()
    inputs.files(agent).withPropertyName("agent")
    // the admission probe lives in org.qntx.card.admission: both packages need the write-point
    // instrumentation for transaction journaling and tear accounting
    jvmArgumentProviders.add {
        listOf("-javaagent:${agent.singleFile.absolutePath}=org/qntx/card,org/qntx/card/admission")
    }
    for (
    name in
    listOf(
        "realCard",
        "realCardPeer",
        "realCardContactless",
        "realCardTear",
        "realCardSacrificial",
    )
    ) {
        providers.gradleProperty(name).orNull?.let { systemProperty(name, it) }
    }
    systemProperty(
        "qntx.reports",
        layout.buildDirectory
            .dir("reports")
            .get()
            .asFile.absolutePath,
    )
    testLogging {
        events(
            org.gradle.api.tasks.testing.logging.TestLogEvent.PASSED,
            org.gradle.api.tasks.testing.logging.TestLogEvent.SKIPPED,
            org.gradle.api.tasks.testing.logging.TestLogEvent.FAILED,
        )
        showStandardStreams = true
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

tasks.check { dependsOn(admissionCap, "compileRealCardJava") }

tasks.test {
    useJUnitPlatform()
    dependsOn(":applet:cap", ":sim:shadowJar")
    inputs.file(cap).withPropertyName("cap")
    inputs.files(agent).withPropertyName("agent")
    systemProperty(
        "qntx.simJar",
        project(":sim")
            .layout.buildDirectory
            .file("libs/card-sim.jar")
            .get()
            .asFile.absolutePath,
    )
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
            "org.qntx.card.SignDifferentialTest",
            // drives the separately built card-sim.jar in a child JVM, whose applet classes
            // PIT never mutates, so it cannot kill any mutant and only costs time
            "org.qntx.card.tests.ServerTest",
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
