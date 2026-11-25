// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
import org.gradle.api.AntBuilder
import org.gradle.kotlin.dsl.withGroovyBuilder
import java.io.File
import java.security.MessageDigest
import java.time.LocalDateTime
import java.util.TreeMap
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/**
 * The Java Card CAP build shared by `:applet:cap` and the test CAPs (architecture §7):
 * one ant-javacard conversion call with the frozen flags `verify=true`, `debug=false`,
 * `ints=false`, then {@link #normalizeCap} so two builds of the same sources give the same
 * SHA-256.
 */
object CapBuild {
    /**
     * Runs the JCDK converter via ant-javacard on the compiled {@code sources} tree: package AID
     * {@code packageAid}, package name {@code pkg}, target API {@code targetSdk}, one applet entry
     * per `(class, AID)` pair of {@code applets}, output to {@code out}.
     */
    fun convertCap(
        ant: AntBuilder,
        antClasspath: String,
        kit: File,
        out: File,
        packageAid: String,
        pkg: String,
        targetSdk: String,
        sources: File,
        applets: List<Pair<String, String>>,
        repoRoot: File,
    ) {
        verifyJcdk(repoRoot, kit)
        ant.withGroovyBuilder {
            "taskdef"(
                "name" to "javacard",
                "classname" to "pro.javacard.ant.JavaCard",
                "classpath" to antClasspath,
            )
            "javacard"("jckit" to kit.absolutePath) {
                "cap"(
                    "targetsdk" to targetSdk,
                    "aid" to packageAid,
                    "package" to pkg,
                    "version" to "1.0",
                    "output" to out.absolutePath,
                    "sources" to sources.absolutePath,
                    "verify" to "true",
                    "debug" to "false",
                    "ints" to "false",
                ) {
                    for ((cls, aid) in applets) {
                        "applet"("class" to cls, "aid" to aid)
                    }
                }
            }
        }
    }

    /**
     * Verifies the pinned JCDK toolchain before conversion (SECURITY.md "Supply chain"):
     * {@code gradle/jcdk-sha256.txt} under {@code root} lists every file of the kit
     * {@code sdks/jc320v26.0_kit} the converter and its Ant task were taken from — each
     * listed file must exist and hash to the recorded SHA-256, and no unlisted file may
     * sit in the kit tree. A missing file, an extra file or a different hash fails the
     * build before the converter runs.
     */
    private fun verifyJcdk(
        root: File,
        kit: File,
    ) {
        val manifest = File(root, "gradle/jcdk-sha256.txt")
        check(manifest.isFile) { "JCDK integrity manifest missing: $manifest" }
        val wanted = TreeMap<String, String>()
        for (line in manifest.readLines()) {
            val t = line.trim()
            if (t.isEmpty() || t.startsWith("#")) {
                continue
            }
            val parts = t.split(Regex("\\s+"), limit = 2)
            require(parts.size == 2 && parts[0].length == 64) {
                "bad line in $manifest: $line"
            }
            wanted[parts[1].trim()] = parts[0]
        }
        val problems = ArrayList<String>()
        val digest = MessageDigest.getInstance("SHA-256")
        for ((path, sha) in wanted) {
            val f = File(root, path)
            if (!f.isFile) {
                problems += "missing $path"
            } else {
                val got =
                    digest.digest(f.readBytes()).joinToString("") { "%02x".format(it) }
                if (got != sha) {
                    problems += "sha256 mismatch $path"
                }
            }
        }
        val rootPath = root.toPath()
        kit
            .walkTopDown()
            .filter { it.isFile }
            .forEach { f ->
                val rel =
                    rootPath.relativize(f.toPath()).toString().replace(File.separatorChar, '/')
                if (!wanted.containsKey(rel)) {
                    problems += "extra file in the JCDK kit: $rel"
                }
            }
        check(problems.isEmpty()) {
            "JCDK toolchain verification failed (gradle/jcdk-sha256.txt):\n  " +
                problems.joinToString("\n  ")
        }
    }

    /**
     * Rewrites the converter's CAP with fixed entry times and without the build-time manifest
     * attributes, so that two builds of the same sources give the same SHA-256 (architecture §7).
     * Entry order and every component byte are kept.
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
}
