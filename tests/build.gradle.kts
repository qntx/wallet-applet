import java.time.LocalDateTime
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

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

val realCard: SourceSet by sourceSets.creating {
    java.srcDir("src/realCard/java")
}

val antJavaCard: Configuration by configurations.creating

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
}

// the real-card suite reuses the test classpath (Vecs, Spec, the host library,
// BouncyCastle) plus the compiled test classes themselves (architecture.md §10)
realCard.compileClasspath += sourceSets.test.get().compileClasspath
realCard.compileClasspath += sourceSets.test.get().output
realCard.runtimeClasspath += sourceSets.test.get().runtimeClasspath
realCard.runtimeClasspath += sourceSets.test.get().output

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

// ---------------------------------------------------------------------------
// Real-card suite (architecture.md §10): the source set compiles in CI, the
// tests themselves run only with -PrealCard=<reader>; see spec/protocol.md §3
// for the silicon admission items they measure.
// ---------------------------------------------------------------------------

val jcKitDir = rootProject.layout.projectDirectory.dir("sdks/${libs.versions.javacard.sdk.get()}")
val targetSdk =
    libs.versions.javacard.target
        .get()

val probeCapFile = layout.buildDirectory.file("cap/qntx-probe.cap")
val memCapFile = layout.buildDirectory.file("cap/qntx-card-memprobe.cap")
val lazyCapFile = layout.buildDirectory.file("cap/qntx-card-lazy.cap")

/**
 * The deferred-construction patch for a staged copy of {@code WalletApplet.java}: the object
 * graph moves from the constructor into {@code lazyInit()}, called on first {@code select()} and
 * {@code process()}, so its persistent writes happen outside the JCRE install journal. Card A's
 * 5,120-byte commit buffer cannot hold them inside {@code install()} (real-card finding: the
 * production CAP fails INSTALL with TransactionException.BUFFER_FULL at {@code new Ecdsa}).
 * Test builds only — the production sources are never touched.
 */
fun applyLazyPatch(wa: File) {
    var text = wa.readText()
    // the nine object-graph fields become assignable on first use
    val fieldMarker = "    private final "
    var count = text.split(fieldMarker).size - 1
    check(count == 9) { "lazy: expected 9 final fields in WalletApplet.java, found $count" }
    text = text.replace(fieldMarker, "    private ")
    val statements =
        "        Const.init();\n" +
            "        mem = new Mem();\n" +
            "        state = new State();\n" +
            "        ModArith modArith = new ModArith(mem);\n" +
            "        Secp256k1 secp = new Secp256k1(mem, modArith);\n" +
            "        Wei25519 wei = new Wei25519(mem);\n" +
            "        identity = new Identity(mem, state, secp);\n" +
            "        session = new Session(mem, state, secp, identity);\n" +
            "        derivation = new Derivation(mem, session, secp, wei, modArith);\n" +
            "        ecdsa = new Ecdsa(mem, session, derivation, secp);\n" +
            "        bip340 = new Bip340(mem, session, derivation, secp, modArith);\n" +
            "        ed25519 = new Ed25519(mem, state, session, derivation, wei, modArith, identity);\n" +
            "        wallet = new Wallet(mem, state, session, identity, derivation);\n"
    val ctorBody =
        "    private WalletApplet(byte[] bArray, short bOffset) {\n" +
            statements +
            "        register(bArray, (short) (bOffset + 1), bArray[bOffset]);\n" +
            "    }"
    count = text.split(ctorBody).size - 1
    check(count == 1) { "lazy: constructor body not found in WalletApplet.java" }
    text =
        text.replace(
            ctorBody,
            "    private WalletApplet(byte[] bArray, short bOffset) {\n" +
                "        register(bArray, (short) (bOffset + 1), bArray[bOffset]);\n" +
                "    }\n\n" +
                "    /** TEST BUILD: the object graph is built on first use (see lazyCap). */\n" +
                "    private void lazyInit() {\n" +
                "        if (mem != null) {\n" +
                "            return;\n" +
                "        }\n" +
                statements +
                "    }",
        )
    val selectBody = "    public boolean select() {\n"
    count = text.split(selectBody).size - 1
    check(count == 1) { "lazy: select() not found" }
    text = text.replace(selectBody, selectBody + "        lazyInit();\n")
    val processBody = "    public void process(APDU apdu) {\n"
    count = text.split(processBody).size - 1
    check(count == 1) { "lazy: process() not found" }
    text = text.replace(processBody, processBody + "        lazyInit();\n")
    wa.writeText(text)
}

/**
 * The same deterministic-CAP rewrite as `:applet:cap` (architecture.md §7): fixed entry times and
 * no build-time manifest attributes, entry order and component bytes kept.
 */
fun normalizeCap(cap: File) {
    val volatile = setOf("Created-By", "Java-Card-CAP-Creation-Time")
    val fixed = LocalDateTime.of(1980, 2, 1, 0, 0)
    val tmp = File(cap.parentFile, cap.name + ".tmp")
    ZipFile(cap).use { zip ->
        ZipOutputStream(tmp.outputStream()).use { out ->
            for (e in zip.entries()) {
                var data = zip.getInputStream(e).readBytes()
                if (e.name == "META-INF/MANIFEST.MF") {
                    data =
                        String(data, Charsets.UTF_8)
                            .split("\r\n")
                            .filterNot { line -> volatile.any { line.startsWith("$it:") } }
                            .joinToString("\r\n")
                            .toByteArray(Charsets.UTF_8)
                }
                val n = ZipEntry(e.name)
                n.timeLocal = fixed
                if (e.method == ZipEntry.STORED) {
                    n.method = ZipEntry.STORED
                    n.size = data.size.toLong()
                    n.compressedSize = data.size.toLong()
                    n.crc = CRC32().apply { update(data) }.value
                }
                out.putNextEntry(n)
                out.write(data)
                out.closeEntry()
            }
        }
    }
    check(tmp.renameTo(cap)) { "cannot replace $cap" }
}

fun javacardCap(
    sources: File,
    packageAid: String,
    packageName: String,
    appletClass: String,
    appletAid: String,
    output: File,
) {
    val kit = jcKitDir.asFile
    check(kit.isDirectory) { "JavaCard SDK missing at $kit: run `git submodule update --init`" }
    output.parentFile.mkdirs()
    ant.withGroovyBuilder {
        "taskdef"("name" to "javacard", "classname" to "pro.javacard.ant.JavaCard", "classpath" to antJavaCard.asPath)
        "javacard"("jckit" to kit.absolutePath) {
            "cap"(
                "targetsdk" to targetSdk,
                "aid" to packageAid,
                "package" to packageName,
                "version" to "1.0",
                "output" to output.absolutePath,
                "sources" to sources.absolutePath,
                "verify" to "true",
                "debug" to "false",
                "ints" to "false",
            ) {
                "applet"("class" to appletClass, "aid" to appletAid)
            }
        }
    }
    normalizeCap(output)
}

val probeCap by tasks.registering {
    group = "build"
    description =
        "Converts the admission probe applet into qntx-probe.cap (a test build, never released)."
    val sources = layout.projectDirectory.dir("src/realCard/javacard/probe")
    inputs.files(antJavaCard).withPropertyName("antJavaCard")
    inputs.dir(sources).withPropertyName("sources")
    inputs.dir(jcKitDir).withPropertyName("jckit")
    outputs.file(probeCapFile)
    doLast {
        javacardCap(
            sources.asFile,
            "F0716E7478FF",
            "org.qntx.card.probe",
            "org.qntx.card.probe.AdmissionProbe",
            "F0716E7478FF01",
            probeCapFile.get().asFile,
        )
    }
}

val lazyCap by tasks.registering {
    group = "build"
    description =
        "Builds qntx-card-lazy.cap: the wallet applet with deferred construction" +
        " (a test build for card A's small install journal, never released)."
    val appletSources =
        project(":applet").layout.projectDirectory.dir("src/main/java")
    val staged = layout.buildDirectory.dir("lazy-src")
    inputs.files(antJavaCard).withPropertyName("antJavaCard")
    inputs.dir(appletSources).withPropertyName("appletSources")
    inputs.dir(jcKitDir).withPropertyName("jckit")
    outputs.file(lazyCapFile)
    doLast {
        val dir = staged.get().asFile
        dir.deleteRecursively()
        appletSources.asFile.copyRecursively(dir)
        applyLazyPatch(File(dir, "org/qntx/card/WalletApplet.java"))
        javacardCap(
            dir,
            "F0716E747800",
            "org.qntx.card",
            "org.qntx.card.WalletApplet",
            "F0716E74780101",
            lazyCapFile.get().asFile,
        )
    }
}

val memProbeCap by tasks.registering {
    group = "build"
    description =
        "Builds qntx-card-memprobe.cap: the lazy test build plus MemProbe instrumentation" +
        " (a test build, never released)."
    val appletSources =
        project(":applet").layout.projectDirectory.dir("src/main/java")
    val probeSources =
        layout.projectDirectory.dir("src/realCard/javacard/memprobe")
    val staged = layout.buildDirectory.dir("memprobe-src")
    inputs.files(antJavaCard).withPropertyName("antJavaCard")
    inputs.dir(appletSources).withPropertyName("appletSources")
    inputs.dir(probeSources).withPropertyName("probeSources")
    inputs.dir(jcKitDir).withPropertyName("jckit")
    outputs.file(memCapFile)
    dependsOn(":applet:cap", lazyCap)
    doLast {
        val dir = staged.get().asFile
        dir.deleteRecursively()
        appletSources.asFile.copyRecursively(dir)
        // the lazy patch first: the memprobe build shares the deferred construction
        applyLazyPatch(File(dir, "org/qntx/card/WalletApplet.java"))
        var commits = 0
        dir.walkTopDown().filter { it.extension == "java" }.forEach { f ->
            var text = f.readText()
            // (a) every commit site reports the unused commit capacity first (§3 item 8)
            val marker = "JCSystem.commitTransaction();"
            var count = text.split(marker).size - 1
            if (count > 0) {
                text = text.replace(marker, "MemProbe.commit();")
                commits += count
            }
            if (f.name == "Session.java") {
                // bisect markers: which open() call throws on card A
                val stages =
                    linkedMapOf(
                        "        secp.randomScalar(w, W_X);" to 1,
                        "        secp.mul(w, W_X, Secp256k1.G, (short) 0, buf, (short) 0);" to 2,
                        "            secp.mul(w, W_X, p, P_HOST, w, W_ZPT);" to 3,
                        "        identity.identity(w, W_A);" to 4,
                        "        mem.sha256.reset();" to 5,
                        "        identity.signHash(w, W_TH, buf, Const.POINT_LEN);" to 6,
                        "        Kdf.kdf(" to 7,
                        "        kce.setKey(w, (short) (W_KEYS + 0));" to 8,
                        "        kcm.setKey(w, (short) (W_KEYS + 16));" to 9,
                        "        kre.setKey(w, (short) (W_KEYS + 32));" to 10,
                        "        krm.setKey(w, (short) (W_KEYS + 48));" to 11,
                        "        state.cert(" to 12,
                    )
                for ((marker, n) in stages) {
                    count = text.split(marker).size - 1
                    check(count == 1) { "memprobe: stage marker not found: $marker" }
                    text = text.replace(marker, "        MemProbe.stage((short) $n);\n" + marker)
                }
            }
            if (f.name == "WalletApplet.java") {
                // (b) per-command log reset and the 0xFE report command
                val begin = "        short lc = receiveAll(apdu);"
                count = text.split(begin).size - 1
                check(count == 1) { "memprobe: receiveAll site not found in WalletApplet.java" }
                text =
                    text.replace(
                        begin,
                        "        MemProbe.begin(buf);\n" + begin,
                    )
                val outerDefault =
                    "            default:\n" +
                        "                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);"
                count = text.split(outerDefault).size - 1
                check(count == 1) { "memprobe: outer default not found in WalletApplet.java" }
                text =
                    text.replace(
                        outerDefault,
                        "            case (byte) 0xFE:\n" +
                            "                len = MemProbe.report(apdu);\n" +
                            "                break;\n" +
                            outerDefault,
                    )
                // (c) the real install window: trivial on the lazy build, kept for the report
                val ctor = "        new WalletApplet(bArray, bOffset);"
                count = text.split(ctor).size - 1
                check(count == 1) { "memprobe: install body not found in WalletApplet.java" }
                text =
                    text.replace(
                        ctor,
                        "        MemProbe.installStart();\n" +
                            ctor + "\n" +
                            "        MemProbe.installEnd();",
                    )
                // (d) 6F00 bisect: record the caught exception's type and reason
                val catchAll =
                    "            // §16.3 item 4: unexpected exceptions map to 6F00, reason codes never escape\n"
                count = text.split(catchAll).size - 1
                check(count == 1) { "memprobe: process catch-all not found" }
                text = text.replace(catchAll, catchAll + "            MemProbe.fault(e);\n")
                // (e) the deferred-construction window of the lazy build
                val guard = "        if (mem != null) {\n            return;\n        }\n"
                count = text.split(guard).size - 1
                check(count == 1) { "memprobe: lazyInit guard not found" }
                text = text.replace(guard, guard + "        MemProbe.lazyStart();\n")
                val lastInit =
                    "        wallet = new Wallet(mem, state, session, identity, derivation);\n"
                count = text.split(lastInit).size - 1
                check(count == 1) { "memprobe: lazyInit tail not found" }
                text = text.replace(lastInit, lastInit + "        MemProbe.lazyEnd();\n")
            }
            f.writeText(text)
        }
        check(commits == 7) { "memprobe: expected 7 commitTransaction sites, found $commits" }
        probeSources.asFile.copyRecursively(dir)
        // a test-only instrumentation class must never reach the release builds
        for (cap in listOf(cap.get().asFile, lazyCapFile.get().asFile)) {
            check(cap.isFile) { "CAP missing at $cap" }
            check(!cap.readBytes().let { String(it, Charsets.ISO_8859_1).contains("MemProbe") }) {
                "CAP at $cap contains a MemProbe reference"
            }
        }
        javacardCap(
            dir,
            "F0716E747800",
            "org.qntx.card",
            "org.qntx.card.WalletApplet",
            "F0716E74780101",
            memCapFile.get().asFile,
        )
    }
}

val realCardOut = providers.gradleProperty("realCardOut")

val realCardTask =
    tasks.register<Test>("realCard") {
        group = "verification"
        description =
            "Runs the real-card suite of architecture.md §10 on a PC/SC reader" +
            " (-PrealCard=<reader>, never in CI; reports \"not run\" without one)."
        useJUnitPlatform()
        testClassesDirs = realCard.output.classesDirs
        classpath = realCard.runtimeClasspath
        dependsOn(":applet:cap", probeCap, memProbeCap, lazyCap)
        // a hardware suite is never up to date
        outputs.upToDateWhen { false }
        systemProperty("qntx.reader", providers.gradleProperty("realCard").orElse("").get())
        systemProperty("qntx.gp", providers.gradleProperty("realCardGp").orElse("").get())
        systemProperty("qntx.cap", cap.get().asFile.absolutePath)
        systemProperty("qntx.lazycap", lazyCapFile.get().asFile.absolutePath)
        // which build the wallet suites run: "production" (default) or the lazy test build
        // (-PrealCardWallet=lazy, needed on card A whose install journal is too small)
        systemProperty(
            "qntx.wallet",
            providers.gradleProperty("realCardWallet").orElse("production").get(),
        )
        systemProperty("qntx.memcap", memCapFile.get().asFile.absolutePath)
        systemProperty("qntx.probecap", probeCapFile.get().asFile.absolutePath)
        systemProperty("qntx.vectors", rootProject.file("spec/vectors").absolutePath)
        systemProperty(
            "qntx.realcard.out",
            realCardOut
                .orElse(
                    layout.buildDirectory
                        .dir("realcard")
                        .get()
                        .asFile.absolutePath,
                ).get(),
        )
        systemProperty(
            "qntx.realcard.differential",
            providers.gradleProperty("realCardDifferential").orElse("1000").get(),
        )
        systemProperty(
            "qntx.realcard.rng",
            providers.gradleProperty("realCardRng").orElse("1048576").get(),
        )
        testLogging {
            events("passed", "skipped", "failed")
            exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        }
    }

// the suite never runs in CI but must always compile there (architecture.md §14.7 R4)
tasks.check { dependsOn(tasks.named("compileRealCardJava")) }
