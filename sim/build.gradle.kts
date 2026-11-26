import org.gradle.process.CommandLineArgumentProvider
import java.io.OutputStream

plugins {
    `java-library`
    alias(libs.plugins.shadow)
}

val apiClassicJar =
    rootProject.layout.projectDirectory.file(
        "sdks/${libs.versions.javacard.sdk.get()}/lib/api_classic-${libs.versions.javacard.target.get()}.jar",
    )

java {
    sourceSets {
        named("main") {
            // Vendored jcardsim fork and the org.qntx.card.sim runtime compile
            // as one source set: the fork patches call into our hooks.
            java.srcDir("jcardsim/src/main/java")
        }
    }
}

dependencies {
    compileOnly(files(apiClassicJar.asFile))
    api(libs.bouncycastle.prov)
    implementation(libs.asm.commons)
    implementation(libs.asm.tree)
    implementation(project(":applet"))
    implementation(project(":host"))
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    // GlobalPlatformPro is the independent oracle of the simulated ISD's SCP03
    // handshake, C-MAC/C-DEC wrapping and GP command formats (IsdTest).
    testImplementation(libs.gppro)
    testImplementation(libs.apdu4j.core)
    testRuntimeOnly(libs.junit.platform.launcher)
    testRuntimeOnly(libs.slf4j.simple)
}

tasks.compileJava {
    options.release = 25
}

// jcardsim merges the *Proxy classes into the Java Card API classes after
// compilation (upstream does this in an ant step). The merged javacard.* /
// javacardx.* classes land in build/jcapi and ride the main source-set
// output, so api_classic itself never reaches a runtime classpath.
val jcapiDir = layout.buildDirectory.dir("jcapi")
val javacardApiStaging = layout.buildDirectory.dir("javacardApiStaging")

val compiledClasses = tasks.compileJava.flatMap { it.destinationDirectory }

val stageJavacardApi =
    tasks.register<Copy>("stageJavacardApi") {
        from(compiledClasses)
        from(zipTree(apiClassicJar.asFile)) {
            exclude("java/**")
        }
        into(javacardApiStaging)
    }

val processJavacardApi =
    tasks.register<JavaExec>("processJavacardApi") {
        dependsOn(stageJavacardApi)
        // api_classic sits on this JVM's classpath only so ASM's
        // COMPUTE_FRAMES can resolve javacard.* supertypes; it is never
        // on a consumer classpath.
        classpath = files(compiledClasses, apiClassicJar, configurations.runtimeClasspath)
        mainClass.set("com.licel.jcardsim.utils.JavaCardApiProcessor")
        // the processor logs every merged method; keep build output readable
        standardOutput = OutputStream.nullOutputStream()
        args(javacardApiStaging.get().asFile.absolutePath)
        inputs.dir(javacardApiStaging)
        outputs.dir(javacardApiStaging)
    }

val collectJcapi =
    tasks.register<Copy>("collectJcapi") {
        dependsOn(processJavacardApi)
        from(javacardApiStaging) {
            include("javacard/**", "javacardx/**")
        }
        into(jcapiDir)
    }

sourceSets {
    named("main") {
        output.dir(mapOf("builtBy" to collectJcapi), jcapiDir)
    }
}

// The simulated ISD verifies an uploaded load file byte-for-byte against the CAP
// the jar was built from (architecture.md §8); the resource lands in card-sim.jar.
val capResource =
    tasks.register<Copy>("capResource") {
        from(project(":applet").tasks.named("cap"))
        into(layout.buildDirectory.dir("capResource"))
    }

sourceSets {
    named("main") {
        resources.srcDir(capResource)
    }
}

val agentJar =
    tasks.register<Jar>("agentJar") {
        archiveBaseName = "sim-agent"
        from(sourceSets["main"].output)
        manifest { attributes("Premain-Class" to "org.qntx.card.sim.Agent") }
    }

// card-sim.jar (architecture.md §8): the whole simulator + applet + host in one fat
// jar whose launcher agent weaves the persistent-write hooks before the applet classes
// load. Signed dependency jars keep their signature files out so the loader does not
// reject the merged classes.
tasks.named<com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar>("shadowJar") {
    archiveFileName = "card-sim.jar"
    manifest {
        attributes(
            "Main-Class" to "org.qntx.card.sim.Server",
            "Launcher-Agent-Class" to "org.qntx.card.sim.Agent",
        )
    }
    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA", "META-INF/*.EC")
    // licence trail inside the jar: the repo AGPL LICENSE, the Apache-2.0 text the vendored
    // jcardsim fork is under, and its NOTICE (Apache-2.0 §4d); no dependency ships a
    // META-INF/LICENSE or NOTICE that would collide with these paths
    from(rootProject.file("LICENSE")) { into("META-INF") }
    from(rootProject.file("LICENSES")) {
        include("Apache-2.0.txt")
        into("META-INF/LICENSES")
    }
    from("jcardsim/NOTICE") { into("META-INF") }
}

configurations.create("agent") {
    isCanBeConsumed = true
    isCanBeResolved = false
    attributes {
        attribute(Usage.USAGE_ATTRIBUTE, objects.named(Usage.JAVA_RUNTIME))
        attribute(LibraryElements.LIBRARY_ELEMENTS_ATTRIBUTE, objects.named(LibraryElements.JAR))
    }
}

artifacts {
    add("agent", agentJar.flatMap { it.archiveFile })
}

tasks.test {
    useJUnitPlatform()
    dependsOn(agentJar)
    jvmArgumentProviders.add(
        CommandLineArgumentProvider {
            listOf("-javaagent:${agentJar.get().archiveFile.get().asFile.absolutePath}=org/qntx/card/sim/probe;sites;dsa=DsaProbe")
        },
    )
}
