# Contributing

Install Python 3.10 or later and Git. Create and activate a virtual environment,
then run from the repository root.

```sh
python -m pip install -e .
python -m unittest discover -s tests -v
```

Run `ai-code-guardian scan --staged` before committing. To check distribution
metadata, install `build` and `twine`, then run `python -m build` and
`python -m twine check --strict dist/*`.

When proposing a rule, explain the risky pattern, give a safe alternative, and
describe common false positives. Include positive and negative tests. For Git
behavior, use a temporary repository and check that observations come from the
intended Git snapshot. Use fabricated values assembled in the test when a
credential format needs testing. Reports must never contain matched values or
source snippets.

Open an issue or pull request for ordinary changes. Follow the [security
policy](SECURITY.md) for vulnerabilities in Guardian itself. Contributions
are distributed under the [MIT license](LICENSE).
