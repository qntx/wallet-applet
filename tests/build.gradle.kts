import java.io.File
import java.security.MessageDigest

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
val realCard: SourceSet by sourceSets.creating {
    java.srcDir("src/realCard/java")
}

// the probe applet also compiles on the JVM: the simulator exercises INS 0x60 (§10)
sourceSets["test"].java.srcDir("src/realCard/javacard/probe")

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
    "realCardImplementation"(sourceSets["test"].output)
    "realCardImplementation"(project(":host"))
    "realCardImplementation"(project(":sim"))
    "realCardImplementation"(project(":applet"))
    "realCardImplementation"(libs.bouncycastle.prov)
    "realCardImplementation"(platform(libs.junit.bom))
    "realCardImplementation"(libs.junit.jupiter)
    "realCardImplementation"(libs.jackson.jr)
    "realCardRuntimeOnly"(libs.junit.platform.launcher)
}

// The test-only card-side halves of the real-card suite (architecture §10):
// src/realCard/javacard/probe is the standalone §3 admission probe (package F0716E7478FF);
// javacard/memprobe is MemProbe plus a patch applied to a copy of the applet sources, so the
// production sources stay untouched — the build fails if the patch no longer applies.
val probeSources = layout.projectDirectory.dir("src/realCard/javacard/probe")
val memprobePatch = layout.projectDirectory.file("src/realCard/javacard/memprobe/memprobe.patch")
val memprobeSourcesDir = layout.buildDirectory.dir("memprobe/src")
val appletSources = project(":applet").layout.projectDirectory.dir("src/main/java")
val probeCapFile = layout.buildDirectory.file("cap/qntx-probe.cap")
val memProbeCapFile = layout.buildDirectory.file("cap/qntx-memprobe.cap")

val compileProbeJava by tasks.registering(JavaCompile::class) {
    source = files(probeSources).asFileTree
    classpath = files(apiClassicJar)
    destinationDirectory.set(layout.buildDirectory.dir("classes/probe"))
    options.release = 8
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Xlint:-options", "-Werror"))
}

val compileMemprobeJava by tasks.registering(JavaCompile::class) {
    dependsOn("prepareMemprobe")
    source = files(memprobeSourcesDir).asFileTree
    classpath = files(apiClassicJar)
    destinationDirectory.set(layout.buildDirectory.dir("classes/memprobe"))
    options.release = 8
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Xlint:-options", "-Werror"))
}

val prepareMemprobe by tasks.registering {
    description =
        "Copies the applet sources, adds MemProbe and applies the memprobe instrumentation patch."
    inputs.dir(appletSources).withPropertyName("appletSources")
    inputs.files(memprobePatch).withPropertyName("patch")
    inputs.files(layout.projectDirectory.file("src/realCard/javacard/memprobe/org/qntx/card/MemProbe.java"))
    outputs.dir(memprobeSourcesDir)
    doLast {
        val dst = memprobeSourcesDir.get().asFile
        delete(dst)
        copy {
            from(appletSources)
            into(dst)
        }
        copy {
            from("src/realCard/javacard/memprobe/org/qntx/card/MemProbe.java")
            into(dst.resolve("org/qntx/card"))
        }
        // `git apply` silently skips untracked trees inside the repository, so use `patch`;
        // a reject is a non-zero exit and fails the build
        val proc =
            ProcessBuilder(
                "patch",
                "-s",
                "-f",
                "--no-backup-if-mismatch",
                "-p1",
                "-i",
                memprobePatch.asFile.absolutePath,
            ).directory(dst)
                .redirectErrorStream(true)
                .start()
        val log = proc.inputStream.readBytes().toString(Charsets.UTF_8)
        check(proc.waitFor() == 0) {
            "memprobe.patch does not apply to the copied applet sources:\n$log"
        }
    }
}

/**
 * Test-only admission probe CAP of the real-card suite (architecture §10): package
 * {@code F0716E7478FF} with the probe applet {@code F0716E7478FF01}. Never part of a release
 * artifact.
 */
val admissionProbeCap by tasks.registering {
    group = "build"
    description = "Converts the §3 admission probe package into tests/build/cap/qntx-probe.cap."
    val kit = jcKitDir.asFile
    val antClasspath = antJavaCard
    inputs.files(antClasspath).withPropertyName("antJavaCard")
    inputs.dir(probeSources).withPropertyName("sources")
    inputs.dir(jcKitDir).withPropertyName("jckit")
    outputs.file(probeCapFile)
    dependsOn(compileProbeJava)
    doLast {
        val out = probeCapFile.get().asFile
        out.parentFile.mkdirs()
        check(kit.isDirectory) { "JavaCard SDK missing at $kit: run `git submodule update --init`" }
        CapBuild.convertCap(
            ant,
            antClasspath.asPath,
            kit,
            out,
            "F0716E7478FF",
            "org.qntx.card.probe",
            libs.versions.javacard.target
                .get(),
            probeSources.asFile,
            listOf("org.qntx.card.probe.AdmissionProbe" to "F0716E7478FF01"),
        )
        CapBuild.normalizeCap(out)
    }
}

/**
 * Test-only memprobe CAP (architecture §10): the production applet sources plus the MemProbe
 * instrumentation of javacard/memprobe — same AIDs, reports memory and commit-capacity data on
 * the outer command {@code 80 FE}. Never part of a release artifact.
 */
val memProbeCap by tasks.registering {
    group = "build"
    description = "Converts the patched memprobe sources into tests/build/cap/qntx-memprobe.cap."
    val kit = jcKitDir.asFile
    val antClasspath = antJavaCard
    inputs.files(antClasspath).withPropertyName("antJavaCard")
    inputs.dir(memprobeSourcesDir).withPropertyName("sources")
    inputs.dir(jcKitDir).withPropertyName("jckit")
    outputs.file(memProbeCapFile)
    dependsOn(prepareMemprobe, compileMemprobeJava)
    doLast {
        // the instrumentation must never reach the release CAP
        check(!appletSources.asFile.resolve("org/qntx/card/MemProbe.java").exists()) {
            "MemProbe.java must not exist in the production applet sources"
        }
        val out = memProbeCapFile.get().asFile
        out.parentFile.mkdirs()
        check(kit.isDirectory) { "JavaCard SDK missing at $kit: run `git submodule update --init`" }
        CapBuild.convertCap(
            ant,
            antClasspath.asPath,
            kit,
            out,
            "F0716E747800",
            "org.qntx.card",
            libs.versions.javacard.target
                .get(),
            memprobeSourcesDir.get().asFile,
            listOf(
                "org.qntx.card.WalletApplet" to "F0716E74780101",
                "org.qntx.card.NdefApplet" to "F0716E74780201",
            ),
        )
        CapBuild.normalizeCap(out)
    }
}

// The real-card suite of architecture §10: never in CI and never run by `check` (check does
// build the suite classes and both probe CAPs). Without -PrealCard=<reader> every test is
// skipped as "not run"; -PrealCardList enumerates the suite as skipped.
tasks.register<Test>("realCard") {
    group = "verification"
    description = "Runs the architecture §10 real-card suite; needs -PrealCard=<reader>."
    testClassesDirs = realCard.output.classesDirs
    classpath = realCard.runtimeClasspath
    useJUnitPlatform()
    dependsOn(":applet:cap", admissionProbeCap, memProbeCap)
    // prebuilt CAPs may be passed in; the in-tree builds are the default
    val prodCap = providers.gradleProperty("realCardCap").orElse(cap.map { it.asFile.absolutePath })
    val memCap =
        providers
            .gradleProperty("realCardMemCap")
            .orElse(memProbeCapFile.map { it.asFile.absolutePath })
    val probeCap =
        providers
            .gradleProperty("realCardProbeCap")
            .orElse(probeCapFile.map { it.asFile.absolutePath })
    doFirst {
        systemProperty("qntx.cap", prodCap.get())
        systemProperty("qntx.memcap", memCap.get())
        systemProperty("qntx.probecap", probeCap.get())
        for (
        (name, path) in
        listOf("qntx.cap" to prodCap, "qntx.memcap" to memCap, "qntx.probecap" to probeCap)
        ) {
            val file = File(path.get())
            val sha =
                MessageDigest
                    .getInstance("SHA-256")
                    .digest(file.readBytes())
                    .joinToString("") { "%02x".format(it) }
            println("$name = ${file.absolutePath}\n  sha256 $sha")
        }
    }
    providers.gradleProperty("realCard").orNull?.let { systemProperty("qntx.reader", it) }
    providers.gradleProperty("qntx.gp").orNull?.let { systemProperty("qntx.gp", it) }
    providers.gradleProperty("realCardDifferential").orNull?.let {
        systemProperty("qntx.realcard.differential", it)
    }
    providers.gradleProperty("realCardSequences").orNull?.let {
        systemProperty("qntx.realcard.sequences", it)
    }
    providers.gradleProperty("realCardPrims").orNull?.let {
        systemProperty("qntx.realcard.prims", it)
    }
    providers.gradleProperty("realCardKeep").orNull?.let {
        systemProperty("qntx.realcard.keep", "true")
    }
    providers.gradleProperty("realCardList").orNull?.let {
        systemProperty("qntx.realcard.list", "true")
    }
    systemProperty(
        "qntx.realcard.out",
        providers
            .gradleProperty("realCardOut")
            .getOrElse(
                layout.buildDirectory
                    .dir("realcard")
                    .get()
                    .asFile.absolutePath,
            ),
    )
    systemProperty("qntx.vectors", rootProject.file("spec/vectors").absolutePath)
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

tasks.check { dependsOn(admissionProbeCap, memProbeCap, "compileRealCardJava") }

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
