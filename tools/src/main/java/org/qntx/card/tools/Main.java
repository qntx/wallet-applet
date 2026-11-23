// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tools;

import java.io.InputStream;
import java.io.PrintStream;
import java.util.function.Function;
import picocli.CommandLine;
import picocli.CommandLine.Command;

/**
 * {@code qntx-card}: the batch provisioning CLI (architecture.md §11, protocol.md §14.3).
 * Subcommands do the card work; {@link #run} exists so tests can drive the CLI in-process with an
 * environment seam and piped streams.
 */
@Command(
        name = "qntx-card",
        mixinStandardHelpOptions = true,
        description = "Install, personalise and inspect qntx cards.")
public final class Main implements Runnable {

    @CommandLine.Spec CommandLine.Model.CommandSpec spec;

    private Main() {}

    public static void main(String[] args) {
        System.exit(run(args, System::getenv, System.in, System.out, System.err));
    }

    /** Executes the CLI; the exit code a shell would see. */
    static int run(
            String[] args,
            Function<String, String> env,
            InputStream in,
            PrintStream out,
            PrintStream err) {
        Ctx ctx = new Ctx(env, in, out, err);
        CommandLine cmd = new CommandLine(new Main());
        cmd.addSubcommand("registry", new RegistryCmd(ctx));
        cmd.addSubcommand("install", new InstallCmd(ctx));
        cmd.addSubcommand("personalise", new PersonaliseCmd(ctx));
        cmd.addSubcommand("shell", new ShellCmd(ctx));
        return cmd.execute(args);
    }

    @Override
    public void run() {
        spec.commandLine().usage(spec.commandLine().getOut());
    }
}
