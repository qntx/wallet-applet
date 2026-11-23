// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
import org.gradle.api.AntBuilder
import org.gradle.kotlin.dsl.withGroovyBuilder
import java.io.File
import java.time.LocalDateTime
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/**
 * The Java Card CAP build shared by `:applet:cap` and `:tests:admissionCap` (architecture §7):
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
    ) {
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
