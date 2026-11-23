// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tools;

import java.io.InputStream;
import java.io.PrintStream;
import java.util.function.Function;

/**
 * The environment of one command invocation: streams and the environment lookup. Tests inject a map
 * for {@code QNTX_ISD_KEY}/{@code QNTX_HSM_PIN} and piped streams; production passes {@code
 * System::getenv}, {@code System.in} and {@code System.out}/{@code err}.
 */
record Ctx(Function<String, String> env, InputStream in, PrintStream out, PrintStream err) {

    /** Prints one failure line and yields the CLI's failure exit code. */
    int fail(String message) {
        err.println(message);
        return 1;
    }
}
