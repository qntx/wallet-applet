import java.io.File
import java.security.MessageDigest
import java.time.Instant
import javax.xml.parsers.DocumentBuilderFactory

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
            rootProject.layout.projectDirectory.asFile,
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
            rootProject.layout.projectDirectory.asFile,
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
    val outDir =
        providers
            .gradleProperty("realCardOut")
            .map { File(it) }
            .getOrElse(
                layout.buildDirectory
                    .dir("realcard")
                    .get()
                    .asFile,
            )
    doFirst {
        // every file the record reads must come from this run: a non-empty output
        // directory is refused (never deleted), the run start is stamped for the
        // record's mtime bound, and stale JUnit XML is removed
        if (outDir.isDirectory) {
            val contents = outDir.listFiles()
            check(contents == null || contents.isEmpty()) {
                "realCard output directory $outDir is not empty " +
                    "(${contents?.size ?: 0} entries) — move it aside or pass" +
                    " -PrealCardOut=<empty dir>; nothing was deleted"
            }
        }
        val xmlDir =
            reports.junitXml.outputLocation
                .get()
                .asFile
        if (xmlDir.isDirectory) {
            xmlDir.listFiles()?.forEach { it.deleteRecursively() }
        }
        outDir.mkdirs()
        File(outDir, ".run-start").writeText(Instant.now().toString() + "\n")
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

// Release evidence (realcard/, release.yml): after a realCard run with a reader, distil
// the run's JUnit XML into <realCardOut>/record.txt in the `qntx-card real-card record 3`
// format — the CAP, the commit and the git trees the run bound, the effective run
// parameters, the card's identity files, totals, one verdict line per suite.txt class
// with its skip reasons, then the timing table — for commit as
// realcard/<cap-sha256>.txt. The task refuses to write a record a checker could accept
// for anything but this run: the git trees under tests/, applet/, host/, sim/ and
// buildSrc/ must be clean and every file it reads must be stamped by this run. Without
// -PrealCard no reader was present and the record must not be written.
val realCardRecord by tasks.registering {
    group = "verification"
    description =
        "Writes <realCardOut>/record.txt from the realCard run's JUnit XML; skipped without" +
        " -PrealCard."
    val readerProp = providers.gradleProperty("realCard")
    val capProp = providers.gradleProperty("realCardCap")
    val memCapProp = providers.gradleProperty("realCardMemCap")
    val probeCapProp = providers.gradleProperty("realCardProbeCap")
    val outProp = providers.gradleProperty("realCardOut")
    onlyIf("no reader run: -PrealCard is absent") { readerProp.isPresent }
    doLast {
        val repoRoot = rootProject.layout.projectDirectory.asFile

        fun git(vararg a: String): String {
            val p =
                ProcessBuilder("git", *a)
                    .directory(repoRoot)
                    .redirectErrorStream(true)
                    .start()
            val out =
                p.inputStream
                    .readAllBytes()
                    .toString(Charsets.UTF_8)
                    .trim()
            check(p.waitFor() == 0) { "git ${a.joinToString(" ")} failed: $out" }
            return out
        }
        val dirty =
            git("status", "--porcelain", "--", "tests", "applet", "host", "sim", "buildSrc")
        check(dirty.isEmpty()) {
            "cannot write the real-card record: the git tree has changes under tests/," +
                " applet/, host/, sim/ or buildSrc/:\n$dirty"
        }
        val outDir =
            outProp
                .map { File(it) }
                .getOrElse(
                    layout.buildDirectory
                        .dir("realcard")
                        .get()
                        .asFile,
                )
        val startFile = File(outDir, ".run-start")
        check(startFile.isFile) {
            "no $startFile — record.txt can only follow a realCard run of this checkout"
        }
        val runStart = Instant.parse(startFile.readText().trim())
        val runStartMs = runStart.toEpochMilli()

        fun fromRun(name: String): File {
            val f = File(outDir, name)
            check(f.isFile) { "realCard evidence $f is missing — the run did not complete" }
            check(f.lastModified() >= runStartMs) {
                "realCard evidence $f predates the run start $runStart — it is stale"
            }
            return f
        }
        val capFile = capProp.map { File(it) }.getOrElse(cap.get().asFile)
        val capSha =
            MessageDigest
                .getInstance("SHA-256")
                .digest(capFile.readBytes())
                .joinToString("") { "%02x".format(it) }
        val suite =
            File(repoRoot, "realcard/suite.txt")
                .readLines()
                .map { it.trim() }
                .filter { it.isNotEmpty() }
        val xmlDir =
            tasks
                .named("realCard", Test::class)
                .get()
                .reports.junitXml.outputLocation
                .get()
                .asFile
        val dbf = DocumentBuilderFactory.newInstance()
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        val db = dbf.newDocumentBuilder()
        var passed = 0
        var failed = 0
        var skipped = 0
        val verdicts = sortedMapOf<String, Pair<String, List<String>>>()
        val xmlFiles =
            xmlDir.listFiles { f -> f.name.startsWith("TEST-") && f.name.endsWith(".xml") }
        check(xmlFiles != null && xmlFiles.isNotEmpty()) {
            "no JUnit XML in $xmlDir — the realCard run did not complete"
        }
        for (file in xmlFiles.sortedBy { it.name }) {
            check(file.lastModified() >= runStartMs) {
                "JUnit XML $file predates the run start $runStart — it is stale"
            }
            val testcases = db.parse(file).getElementsByTagName("testcase")
            var total = 0
            var bad = 0
            var skip = 0
            val reasons = mutableListOf<String>()
            for (i in 0 until testcases.length) {
                val tc = testcases.item(i) as org.w3c.dom.Element
                total++
                if (
                    tc.getElementsByTagName("failure").length > 0 ||
                    tc.getElementsByTagName("error").length > 0
                ) {
                    bad++
                } else {
                    val skippedNodes = tc.getElementsByTagName("skipped")
                    if (skippedNodes.length > 0) {
                        skip++
                        val node = skippedNodes.item(0) as org.w3c.dom.Element
                        val why = node.getAttribute("message").ifEmpty { node.textContent }
                        reasons += "${tc.getAttribute("name")}: ${why.trim()}"
                    }
                }
            }
            passed += total - bad - skip
            failed += bad
            skipped += skip
            val name = file.name.removePrefix("TEST-").removeSuffix(".xml")
            verdicts[name] =
                (
                    if (bad > 0) {
                        "FAIL"
                    } else if (skip == total) {
                        "SKIP"
                    } else {
                        "PASS"
                    }
                ) to reasons
        }
        for (name in verdicts.keys) {
            check(suite.contains(name)) {
                "test class $name ran but is not in realcard/suite.txt"
            }
        }
        val hex = { f: File -> f.readBytes().joinToString("") { "%02x".format(it) } }

        // the effective run parameters of the realCard task — the checker accepts a
        // record only for the release values (RealCardCheck.RELEASE_PARAMS)
        fun prop(name: String): String? = providers.gradleProperty(name).orNull
        val params =
            "differential=" + (prop("realCardDifferential") ?: "1000") +
                " sequences=" + (prop("realCardSequences") ?: "80") +
                " prims=" + (prop("realCardPrims")?.ifBlank { null } ?: "all") +
                " keep=" + (prop("realCardKeep") != null) +
                " cap=" + (if (capProp.isPresent) "prebuilt" else "tree") +
                " memcap=" + (if (memCapProp.isPresent) "prebuilt" else "tree") +
                " probecap=" + (if (probeCapProp.isPresent) "prebuilt" else "tree")
        val record = File(outDir, "record.txt")
        val text =
            buildString {
                append("qntx-card real-card record 3\n")
                append("cap ").append(capSha).append('\n')
                append("commit ").append(git("rev-parse", "HEAD")).append('\n')
                append("tree-tests ").append(git("rev-parse", "HEAD:tests")).append('\n')
                append("tree-applet ").append(git("rev-parse", "HEAD:applet")).append('\n')
                append("tree-host ").append(git("rev-parse", "HEAD:host")).append('\n')
                append("tree-sim ").append(git("rev-parse", "HEAD:sim")).append('\n')
                append("tree-buildSrc ").append(git("rev-parse", "HEAD:buildSrc")).append('\n')
                append("params ").append(params).append('\n')
                append("date ").append(runStart).append('\n')
                append("reader ").append(readerProp.get()).append('\n')
                append("atr ").append(fromRun("atr.txt").readText().trim()).append('\n')
                append("cplc ").append(hex(fromRun("cplc.bin"))).append('\n')
                append("identify ").append(hex(fromRun("identify.bin"))).append('\n')
                append("apdu-log-sha256 ")
                    .append(
                        MessageDigest
                            .getInstance("SHA-256")
                            .digest(fromRun("apdu.log").readBytes())
                            .joinToString("") { "%02x".format(it) },
                    ).append('\n')
                // a MISSING or FAIL verdict line counts against the record's `failed`
                var classFailed = 0
                val classes = StringBuilder()
                for (name in suite) {
                    val v = verdicts[name]
                    val verdict = v?.first ?: "MISSING"
                    if (verdict != "PASS" && verdict != "SKIP") {
                        classFailed++
                    }
                    classes
                        .append("class ")
                        .append(name)
                        .append(' ')
                        .append(verdict)
                        .append('\n')
                    if (v != null) {
                        for (r in v.second) {
                            classes.append("  skip ").append(r).append('\n')
                        }
                    }
                }
                append("passed ").append(passed).append('\n')
                append("failed ").append(failed + classFailed).append('\n')
                append("skipped ").append(skipped).append('\n')
                append(classes)
                append('\n').append(fromRun("timing.md").readText())
            }
        record.writeText(text)
        println("wrote ${record.absolutePath}")
    }
}

// release.yml runs this on the tag: realcard/<sha256 of the released CAP>.txt must be
// consistent with this build — the record's cap, commit, five git trees, run parameters,
// failure count and class lines are checked by org.qntx.card.RealCardCheck.
tasks.register<JavaExec>("checkRealCardRecord") {
    group = "verification"
    description =
        "Fails unless realcard/<cap-sha256>.txt is consistent with this build (§10)."
    classpath = sourceSets["test"].runtimeClasspath
    mainClass.set("org.qntx.card.RealCardCheck")
    dependsOn(tasks.named("testClasses"))
    doFirst {
        // the release job checks the CAP it ships: build/dist wins, the cap task
        // output is the standalone default
        val distCap =
            rootProject.layout.buildDirectory
                .file("dist/qntx-card.cap")
                .get()
                .asFile
        val capFile = if (distCap.isFile) distCap else cap.get().asFile
        args(
            rootProject.layout.projectDirectory.asFile.absolutePath,
            capFile.absolutePath,
        )
    }
}

tasks.named("realCard") { finalizedBy(realCardRecord) }

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
    jvmArgumentProviders.add {
        // the sites weave costs ~55% wall time: the normal suite runs without it
        // (B2's gateSweep task weaves it; B3's persistent faults also arm call sites)
        listOf("-javaagent:${agent.singleFile.absolutePath}=org/qntx/card")
    }
    filter {
        excludeTestsMatching("org.qntx.card.GateSweepTest")
        // the predicate self-checks inject deliberate releases; they belong to gateSweep
        excludeTestsMatching("org.qntx.card.GateSweepPredicateTest")
    }
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

val gateSweep by tasks.registering(Test::class) {
    description =
        "Single-fault sweep over every gate path: re-runs each attack scenario once per " +
        "executed branch, invoke and woven result (GateSweepTest)."
    testClassesDirs = sourceSets["test"].output.classesDirs
    classpath = sourceSets["test"].runtimeClasspath
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
    jvmArgumentProviders.add {
        listOf("-javaagent:${agent.singleFile.absolutePath}=org/qntx/card;sites")
    }
    systemProperty("qntx.cap", cap.get().asFile.absolutePath)
    systemProperty("qntx.vectors", rootProject.file("spec/vectors").absolutePath)
    systemProperty(
        "qntx.reports",
        layout.buildDirectory
            .dir("reports")
            .get()
            .asFile.absolutePath,
    )
    filter {
        // ReviewMutantTest's persistent site faults need the same weave; it self-skips
        // in the unwoven `test` task, as do the site-armed fault tests
        includeTestsMatching("org.qntx.card.GateSweepTest")
        includeTestsMatching("org.qntx.card.ReviewMutantTest")
        includeTestsMatching("org.qntx.card.GateSweepPredicateTest")
        includeTestsMatching("org.qntx.card.DerivationFaultTest")
        includeTestsMatching("org.qntx.card.ReceiveBoundTest")
    }
    testLogging {
        events("failed", "passed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        showStandardStreams = true
    }
}

tasks.check { dependsOn(gateSweep) }

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
                "-javaagent:${agent.singleFile.absolutePath}=org/qntx/card;sites",
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
            // re-runs whole attack scenarios per instruction site and kills nothing PIT
            // needs; it is the mutation gate's sweep, not a mutation target
            "org.qntx.card.GateSweepTest",
            "org.qntx.card.GateSweepPredicateTest",
            // arms faults at numbered instruction sites; PIT's coverage probes insert
            // invokes that shift the numbering, so the armed sites miss — the mutant
            // assertions still run under gateSweep where the weaving is ours alone
            "org.qntx.card.ReviewMutantTest",
            "org.qntx.card.DerivationFaultTest",
            "org.qntx.card.ReceiveBoundTest",
        )
    mutators = listOf("STRONGER")
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
