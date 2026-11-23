// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0
package org.qntx.card.vectors;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/**
 * Java generator (BouncyCastle) of the files of spec/protocol.md §18. Usage: {@code Generate
 * <outDir>}. Each implementation stage adds the files it owns to {@link #FILES}; {@code
 * selftest.json} is the harness's own agreement check and is never committed.
 */
public final class Generate {
    private static final Map<String, Document> FILES =
            Map.ofEntries(
                    Map.entry("selftest.json", (Document) Selftest::document),
                    Map.entry("kdf.json", (Document) KdfDoc::document),
                    Map.entry("cert.json", (Document) CertDoc::document),
                    Map.entry("session.json", (Document) SessionDoc::document),
                    Map.entry("record.json", (Document) RecordDoc::document),
                    Map.entry("access.json", (Document) AccessDoc::document),
                    Map.entry("wrap.json", (Document) WrapDoc::document),
                    Map.entry("derivation.json", (Document) DerivationDoc::document),
                    Map.entry("ecdsa.json", (Document) EcdsaDoc::document),
                    Map.entry("bip340.json", (Document) Bip340Doc::document),
                    Map.entry("ed25519.json", (Document) Ed25519Doc::document),
                    Map.entry("transfer.json", (Document) TransferDoc::document));

    private Generate() {}

    public static void main(String[] args) throws IOException {
        Path out = Path.of(args[0]);
        Files.createDirectories(out);
        for (Map.Entry<String, Document> f : FILES.entrySet()) {
            Files.writeString(
                    out.resolve(f.getKey()),
                    Json.encode(f.getValue().build()),
                    StandardCharsets.US_ASCII);
        }
    }

    @FunctionalInterface
    interface Document {
        Object build();
    }
}
