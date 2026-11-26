// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/**
 * {@code realcard/suite.txt} is the bound list the record gate checks a run against: it must name
 * exactly the {@code *RealCardTest} classes under {@code tests/src/realCard/java}, sorted — a new
 * suite class without a list update fails here, never silently at the record.
 */
final class RealCardSuiteTest {
    @Test
    void suiteTxtListsEveryRealCardTest() throws Exception {
        Path root =
                Path.of(System.getProperty("qntx.vectors", "spec/vectors")).getParent().getParent();
        List<String> suite = Files.readAllLines(root.resolve("realcard/suite.txt"));
        Path dir = root.resolve("tests/src/realCard/java/org/qntx/card/real");
        List<String> classes;
        try (var stream = Files.list(dir)) {
            classes =
                    stream.filter(f -> f.getFileName().toString().endsWith("RealCardTest.java"))
                            .map(
                                    f ->
                                            "org.qntx.card.real."
                                                    + f.getFileName()
                                                            .toString()
                                                            .replace(".java", ""))
                            .sorted()
                            .collect(Collectors.toList());
        }
        assertEquals(classes, suite, "realcard/suite.txt is out of date");
    }
}
