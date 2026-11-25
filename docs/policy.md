# Repository policy

Create `.ai-code-guardian.json` at the repository root. A policy is an optional
UTF-8 JSON file, up to 64 KiB. An empty object uses the built-in defaults.
For a starting point, copy [the example policy](../examples/policy.json) and
adapt its rule IDs, paths, reasons, and expiry dates.

```json
{
  "rules": {
    "ACG104": "error"
  },
  "suppressions": [
    {
      "rule": "ACG003",
      "path": "tests/fixtures/**/*.txt",
      "reason": "Synthetic credentials exercise the parser.",
      "expires": "2027-12-31"
    }
  ]
}
```

## Rules and exceptions

- `rules` maps [source rule IDs](rules.md) to `warning`, `error`, or `off`.
  Omitted rules keep their default severity. Source scans fail on both warnings
  and errors by default. With `--fail-on error`, a warning is still reported
  and only errors trigger code 1. Use `off` for a deliberate repository-wide
  disablement.
- Each `suppressions` entry requires a source rule ID, a path pattern, a
  non-empty reason and a date in `YYYY-MM-DD` format. It matches until the
  end of that date in UTC. An optional positive integer `line` limits the
  exception to that one-based line number in the scanned version of the file.
  Review line-specific exceptions when code moves.
- Patterns are case-sensitive and match the entire relative path. Use
  forward slashes on every operating system. `*`, `?` and character classes
  match within a component. A whole `**` component matches zero or more
  levels, so `tests/fixtures/**/*.txt` covers files directly inside
  `tests/fixtures` as well as files in its subdirectories. For a renamed
  file, the pattern is matched against the destination.
- Reports count suppressed findings and note expired entries. Reasons
  remain in the policy file. Use a brief explanation and keep secrets out of
  the file. Dependency advisories from the separate `audit` command are
  outside this policy.

## Which policy is used?

| Command | Policy used by default | Anchor for path patterns |
| --- | --- | --- |
| `scan --staged` | Git index at the repository root | Git repository root |
| `scan --diff BASE` | The policy committed at `BASE`, even if the diff starts at an older merge base | Git repository root |
| `scan` or `scan --path PATH` | The policy in the current directory | Current directory |

For a full scan of a path outside the current directory, only the global
rule levels apply. For example, run `scan --path src` from the repository
root if you want a pattern starting with `src/` to apply.

An absent default policy uses built-in settings. An explicit `--config FILE`
overrides the default policy, keeps the same path anchor, and fails if the
file is missing. An invalid or unreadable selected policy produces exit
code 2. Preview a proposed policy before committing it with:

```sh
ai-code-guardian scan --diff origin/main --config .ai-code-guardian.json
```

Use a base reference controlled by maintainers in CI. The supplied PR workflow
uses GitHub's base SHA. A pull request's policy edit affects future PR scans
after it is merged. When consuming Guardian in a different repository,
use the example workflow with a trusted Guardian commit.
