# Changelog

## 1.2.0

- Detect literal TLS verification disablement on recognized Requests Sessions,
  both on individual calls and on the Session's default settings.
- Add a pre-commit hook that scans staged lines directly from the Git index.
- Add `scan --fail-on error` to keep warnings in reports while reserving
  finding-related failures for errors. The default still fails on warnings.

## 1.1.0

- Configure source rule levels in a repository policy or an explicit JSON file.
- Add path-scoped exceptions with a reason, expiry date, and optional line.
  Reports count suppressed findings and note expired exceptions.
- Read policy from the base commit during diff scans so a proposed policy
  change cannot silence findings in the same pull request.
- Show changed-line annotations in GitHub pull request checks and retain the
  SARIF artifact for the full report.

## 1.0.0

- Scan UTF-8 files for common secret formats and selected unsafe Python calls.
- Review newly added or replaced lines in the Git index or a committed diff.
- Optionally audit exact Python dependency pins with PyPA's pip-audit.
- Emit text, JSON, or SARIF 2.1.0 reports without secret snippets.
- Include a GitHub Actions workflow and a cross-platform CI matrix.
