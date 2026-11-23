// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tools;

import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;

/**
 * {@code qntx-card registry}: print the GP registry in the baseline text format (protocol.md §14.3
 * step 6 — admission records this as the batch's factory registry baseline).
 */
@Command(name = "registry", description = "Print the card's GlobalPlatform registry.")
final class RegistryCmd implements Callable<Integer> {

    private final Ctx ctx;

    RegistryCmd(Ctx ctx) {
        this.ctx = ctx;
    }

    @Mixin Transport transport;

    @Option(
            names = "--scp",
            required = true,
            description = "secure channel protocol of the batch: 03 or 02-55")
    String scp;

    @Override
    public Integer call() {
        try (Transport t = transport) {
            var session =
                    Gp.open(
                            transport.open(),
                            Gp.isdKeys(ctx.env().apply(Gp.ISD_KEY_ENV)),
                            Gp.scp(scp));
            for (String line : RegistryText.lines(session.getRegistry())) {
                ctx.out().println(line);
            }
            return 0;
        } catch (Exception e) {
            return ctx.fail("registry: " + message(e));
        }
    }

    static String message(Throwable e) {
        String m = e.getMessage();
        return m == null ? e.getClass().getSimpleName() : m;
    }
}
