# AI Code Guardian

AI Code Guardian is a local command-line security check for code review. It
flags common credential formats and selected unsafe Python calls on lines you
are about to commit or introduce in a pull request. Use it on human-written or
AI-generated code with the same rules. The source scanner uses deterministic
checks and runs without an AI model, API key, or runtime dependencies.

## Install

Use Python 3.10 or newer. Git is required for Git modes, with Git 2.30 or
newer recommended. From this repository, preferably in an activated virtual
environment:

```sh
python -m pip install .
ai-code-guardian --version
```

The package can also be run as `python -m ai_code_guardian`. The repository is
the installation source for this release. A PyPI publication is not assumed.

## Review code

```sh
# Review exactly what is staged for commit, including the first commit.
git add review.py
ai-code-guardian scan --staged

# Review new lines on the current branch relative to its merge base with main.
git fetch origin
ai-code-guardian scan --diff origin/main

# Review a committed tip other than the current HEAD.
ai-code-guardian scan --diff origin/main --head feature-branch

# Review a whole file or directory in the working tree.
ai-code-guardian scan --path src
```

`scan` with no flags scans the current directory. Full scans walk the specified
path without applying Git ignore rules. They omit Git metadata, common build
and virtual environment directories during traversal, and avoid symbolic
links and Windows reparse points. Git modes use the selected snapshots across the whole repository,
including when invoked from a subdirectory. They skip deleted lines and
non-regular entries such as submodules and symlinks. A rename recognized by
Git reports changed lines at the destination. A new or unrecognized renamed
file contributes every line. Diff mode reads committed Git objects. Staged
mode reads the index even when the working tree contains different text.

See the [worked example](examples/README.md) and the [rule reference](docs/rules.md).

## Scan automatically before commits

AI Code Guardian provides a [pre-commit](https://pre-commit.com/) hook for
Python 3.10+ and pre-commit 3.2.0+. Add the following to the `repos` list in
your repository's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/msol3sco/ai-code-guardian
    rev: v1.2.0
    hooks:
      - id: ai-code-guardian
```

Install the hook from your repository root:

```sh
python -m pip install pre-commit
pre-commit install
```

The hook runs `scan --staged` when you commit and reads the Git index.
By default, any unsuppressed finding stops the commit. To allow warning-only
commits and still see their warnings, add `args: [--fail-on, error]` and
`verbose: true` under the hook entry, as in the
[example configuration](examples/pre-commit-config.yaml). Operational
errors still stop the commit. For a full scan, run
`ai-code-guardian scan --path .` directly.

## Configure source rules

Add a `.ai-code-guardian.json` file at the repository root to change
rule levels or record scoped exceptions. Each exception has a reason and an
expiry date. Reports count suppressed findings, and expired exceptions stop
suppressing them automatically.

Staged scans read the index policy. Diff scans read the policy from the
specified base commit, so the proposed policy does not affect its own pull
request scan. Full scans use the policy in the current directory. Use
`--config FILE` to preview a local policy explicitly. See the
[policy reference](docs/policy.md) for the format and examples.

## Audit pinned Python dependencies

Install the optional audit extra into the same virtual environment. Supply a
UTF-8 requirements file with one exact `name==version` per line. Blank lines
and comments are accepted.

```sh
python -m pip install ".[audit]"
ai-code-guardian audit --requirements requirements.txt --format json
```

This command sends the listed package names and versions to PyPI through
[PyPA pip-audit](https://github.com/pypa/pip-audit). Add transitive packages
to your pinned input if you want them checked. The command does not resolve
dependencies, install packages from the input, or apply fixes. URLs, includes,
markers, extras, hashes, range constraints, and editable requirements are
outside this input format. An unavailable auditor or database, invalid input,
or a partially completed audit produces exit code 2.

## Reports and exit codes

```sh
ai-code-guardian scan --staged --format json
ai-code-guardian scan --diff origin/main --format sarif --output guardian.sarif
```

Text is the default. Choose `--format json` for automation or `--format sarif`
for SARIF 2.1.0 consumers. Reports go to standard output unless you request a
new file with `--output`. The CLI refuses to overwrite an existing file.

| Exit code | Meaning |
| --- | --- |
| 0 | The checks completed without a finding at the selected failure level. Review any warnings and skip notes. |
| 1 | At least one finding met the selected failure level. |
| 2 | Invalid usage or policy, an I/O or Git error, or an incomplete audit. Inspect the errors before relying on the results. |

Source scans default to `--fail-on warning`, which fails on any unsuppressed
finding. With `--fail-on error`, warnings stay in reports and GitHub
annotations. Severity comes from the rule or repository policy, and the
threshold only changes the exit code. The separate `audit` command exits
with 1 when it finds a dependency advisory.

Reports use one-based line numbers. Source findings include a relative file
path, rule ID, severity, and remediation message. Audit findings also include
the package, version, and advisory ID.

## GitHub Actions

This repository includes a [Guardian workflow](.github/workflows/guardian.yml)
that installs the pull request's version of Guardian and reviews changed
lines at the pull request head. Findings appear as file-and-line annotations
in the pull request's **Checks** tab and may also appear in **Files changed**.
The workflow keeps the complete report as a SARIF artifact and fails for
unsuppressed findings or scan errors. A separate
[CI workflow](.github/workflows/ci.yml) tests and builds the package.

To scan a different repository, copy the [consumer workflow](examples/guardian.yml)
to that repository's `.github/workflows/guardian.yml`. Set the owner and full
commit SHA of a trusted Guardian version 1.1.0 or later. The example runs on
`pull_request` with read-only permissions, and annotations use standard
GitHub Actions commands. GitHub permits up to 10 warning and 10 error
annotations per step. The SARIF file remains downloadable for all
unsuppressed findings. See the [verification steps](examples/README.md).

For a before-and-after example with public check runs and a SARIF excerpt,
see the [reproducible GitHub Actions demo](docs/demo.md).

## Privacy and limitations

- Source scanning runs on the machine or CI runner you choose. It sends no
  code, snippets, or token values over the network. It does not verify whether
  a detected credential is valid. The optional audit makes network requests
  containing the pinned package names and versions.
- Source reports omit matched values and source snippets. File paths and line
  numbers are included, and filenames may contain sensitive information.
  Review reports before sharing them. A workflow artifact is stored on GitHub.
- Rules are heuristic. Expect both missed findings and false positives.
  Binary and non-UTF-8 files are skipped. The limit is 1 MiB per file or Git
  blob, including the previous blob in a Git comparison. Python syntax the
  running interpreter cannot parse gets secret checks only, with a note.
- Git scans review changed evidence lines and exclude previous commits,
  untracked files, and unchanged lines even inside a changed file. A change
  to a nearby import or variable can change the meaning of unmodified lines
  without producing a finding. Run a full scan when you want broader coverage.
- Advisory results depend on the exact pins provided and the current contents
  of PyPI's advisory data. Use code review and other security checks suited to
  your project alongside Guardian.

## Contribute

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and the
[MIT license](LICENSE).
