// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * PIT's {@code RemoveConditionalMutator} can leave the whole tail of a method dead; a hotswap of
 * such a mutant re-runs this transformer, which recomputes {@code max_locals} over reachable code
 * only. The {@code LocalVariableTable} must not survive weaving when it names slots that no longer
 * exist, or the JVM rejects the redefinition with a {@link ClassFormatError}.
 */
final class AgentDeadCodeTest {

    /** Defines the probe in a child loader so the same name can be redefined per step. */
    private static final class Def extends ClassLoader {
        Def() {
            super(AgentDeadCodeTest.class.getClassLoader());
        }

        Class<?> define(byte[] bytes) {
            return defineClass("org.qntx.card.sim.probe.DeadProbe", bytes, 0, bytes.length);
        }
    }

    @Test
    void aDeadTailCannotDangleTheLocalVariableTable() throws IOException {
        byte[] mutant;
        try (InputStream in =
                AgentDeadCodeTest.class
                        .getClassLoader()
                        .getResourceAsStream("org/qntx/card/sim/probe/DeadProbe.class")) {
            mutant = in.readAllBytes();
        }
        // Turn `if (v == 0)` into a nop so `return 0` always runs and the `tail` local dies with
        // the unreachable tail, the same shape PIT's EQUAL_IF mutants have. DeadProbe compiles
        // to iload_0; ifne +5; iconst_0; ireturn; bipush 7; istore_1; iload_1; ireturn, so the
        // three bytes before the ireturn sequence are the ifne to replace with pop; nop; nop
        byte[] tail = {0x03, (byte) 0xAC, 0x10, 0x07, 0x3C, 0x1B, (byte) 0xAC};
        int at = -1;
        for (int i = 4; i + tail.length <= mutant.length; i++) {
            boolean match = true;
            for (int j = 0; j < tail.length; j++) {
                match &= mutant[i + j] == tail[j];
            }
            if (match) {
                assertTrue(at < 0 && mutant[i - 3] == (byte) 0x9A);
                at = i;
            }
        }
        assertTrue(at > 0);
        mutant[at - 3] = 0x57;
        mutant[at - 2] = 0;
        mutant[at - 1] = 0;
        // sanity: the patched mutant itself is a valid class, like PIT's hotswap payload
        assertDoesNotThrow(() -> new Def().define(mutant));
        byte[] woven =
                new Agent.AppletTransformer(Set.of("org/qntx/card/sim/probe"), false)
                        .transform(
                                AgentDeadCodeTest.class.getClassLoader(),
                                "org/qntx/card/sim/probe/DeadProbe",
                                null,
                                null,
                                mutant);
        assertNotNull(woven);
        assertDoesNotThrow(() -> new Def().define(woven));
    }
}
