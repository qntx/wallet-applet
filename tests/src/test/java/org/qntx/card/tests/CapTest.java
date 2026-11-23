// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import org.junit.jupiter.api.Test;

/**
 * The converted CAP carries the identifiers of protocol.md §2, so the simulator installs the same
 * package and applet AIDs that a card loads (JCVM 3.0.5 §6.4 Header and §6.5 Applet components).
 */
final class CapTest {
    private static final int HEADER_TAG = 1;
    private static final int APPLET_TAG = 3;
    private static final int MAGIC = 0xDECAFFED;

    @Test
    void headerNamesThePackageAid() throws IOException {
        ByteBuffer header = component("Header.cap", HEADER_TAG);
        assertEquals(MAGIC, header.getInt());
        // CAP minor, major, flags; then the package's minor and major version.
        header.position(header.position() + 5);
        assertArrayEquals(Spec.PACKAGE_AID, aid(header));
    }

    @Test
    void appletComponentListsWalletAndNdefApplets() throws IOException {
        ByteBuffer applets = component("Applet.cap", APPLET_TAG);
        assertEquals(2, applets.get());
        assertArrayEquals(Spec.WALLET_AID, aid(applets));
        applets.getShort();
        assertArrayEquals(Spec.NDEF_APPLET_AID, aid(applets));
        applets.getShort();
        assertEquals(0, applets.remaining());
    }

    private static byte[] aid(ByteBuffer b) {
        byte[] aid = new byte[b.get()];
        b.get(aid);
        return aid;
    }

    private static ByteBuffer component(String name, int tag) throws IOException {
        try (ZipFile cap = new ZipFile(System.getProperty("qntx.cap"))) {
            ZipEntry entry = cap.getEntry("org/qntx/card/javacard/" + name);
            assertNotNull(entry, name);
            byte[] data = cap.getInputStream(entry).readAllBytes();
            ByteBuffer b = ByteBuffer.wrap(data);
            assertEquals(tag, b.get());
            assertEquals(data.length - 3, Short.toUnsignedInt(b.getShort()));
            return ByteBuffer.wrap(Arrays.copyOfRange(data, 3, data.length));
        }
    }
}
