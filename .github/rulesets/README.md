# Repository protection

Anyone with write access can push a branch whose copy of a workflow says anything: GitHub runs the
definition from the ref that triggered it, so `needs: gate` in `release.yml` binds only an
unmodified file. The rulesets in this directory are evaluated by GitHub itself and are what stop a
writer — or a leaked token with `contents: write` — from changing `main` or cutting a release.

| Guarantee                                                  | Enforced by                                  |
| ---------------------------------------------------------- | -------------------------------------------- |
| Nothing reaches `main` without a pull request              | Ruleset `main` (`main.json`)                 |
| …and every job of `ci.yml` passed on the up-to-date branch | Ruleset `main`: required checks, strict      |
| `main` is never force-pushed or deleted                    | Ruleset `main`                               |
| Only admins create, move or delete `v*` release tags       | Ruleset `release tags` (`release-tags.json`) |

The required checks are the jobs of `ci.yml`, which runs on every pull request: `lint`, `build`,
`vectors` and `sweep (0)` … `sweep (7)`. Renaming a job or changing the sweep shard count changes
these names; update `main.json` and rerun `apply.sh` in the same pull request, or `main` stops
accepting merges.

## Apply

Run as a repository admin:

```bash
.github/rulesets/apply.sh
```

It creates or updates the rulesets `main` and `release tags` and turns on deleting head branches
after merge. Check the result:

```bash
gh api repos/qntx/wallet-applet/rulesets --jq '.[] | {name, target, enforcement}'
```

## Single maintainer

The repository is run by one maintainer today: `main.json` requires a pull request and the status
checks but no approving review (nobody else could give one).

- Kept: nothing reaches `main` without a pull request and green checks; release tags are
  admin-only, so a non-admin writer or a leaked `contents: write` token cannot trigger
  `release.yml`.
- Given up: a second person. Whoever controls the maintainer's GitHub account can merge and tag.
  The account's own 2FA is the control.

When a second maintainer joins: set `required_approving_review_count` to 1 with
`require_code_owner_review` and `require_last_push_approval` in `main.json`, add a
`.github/CODEOWNERS`, and rerun `apply.sh`.
