# Real-card records

One record per released CAP, named `<cap-sha256>.txt`: a passing run of the real-card suite
(`docs/architecture.md` §10) on that exact CAP, produced by
`./gradlew :tests:realCard -PrealCard=<reader>` at `tests/build/realcard/record.txt` and copied
here before tagging. `release.yml` refuses a tag whose CAP has no record with `failed 0` and a
`PASS` line for `org.qntx.card.real.InstallRealCardTest`.
