# Reproducible GitHub Actions demo

[Status Relay](https://github.com/msol3sco/ai-code-guardian-demo) is an HTTPS health-check CLI with JSON configuration,
expected status codes, request timeouts, a JSON report, and tests that mock HTTP
requests. The AI Code Guardian maintainer created it as a controlled
demonstration. Its workflow installs [Guardian v1.1.0](https://github.com/msol3sco/ai-code-guardian/releases/tag/v1.1.0)
from [a pinned commit](https://github.com/msol3sco/ai-code-guardian/commit/23fdbdc08239e6a62b7214a8281d998768303faf) and scans the pull
request diff without executing the application.

## What happened

[Demo pull request #1](https://github.com/msol3sco/ai-code-guardian-demo/pull/1) adds a User-Agent so service operators can
recognize Status Relay requests. The first commit deliberately adds
`verify=False` to the HTTPS request. The second commit removes that override,
keeps the User-Agent, and asserts that TLS verification stays enabled.

| Snapshot | Guardian | Unit tests |
| --- | --- | --- |
| [Before the fix](https://github.com/msol3sco/ai-code-guardian-demo/blob/37a241e7451c5af638338a0bc6c23132532abcf4/src/status_relay/probes.py#L26) | [Failed with ACG104](https://github.com/msol3sco/ai-code-guardian-demo/actions/runs/45701727688) | [Passed](https://github.com/msol3sco/ai-code-guardian-demo/actions/runs/45701727883) |
| [After the fix](https://github.com/msol3sco/ai-code-guardian-demo/commit/9e6846b5a4876692439db23cc5584e81c8c0bfb3) | [Passed with zero findings](https://github.com/msol3sco/ai-code-guardian-demo/actions/runs/45701931195) | [Passed](https://github.com/msol3sco/ai-code-guardian-demo/actions/runs/45701928782) |

The [first job](https://github.com/msol3sco/ai-code-guardian-demo/actions/runs/45701727688/job/139513284771) shows the annotation. The downloaded
`guardian-sarif` artifacts record the exit codes and results. The first scan exited with code 1
and recorded the warning below. The second exited with code 0 and had no
results. The excerpt preserves the rule ID, severity, file, and line after the
workflow artifacts expire.

```json
{
  "ruleId": "ACG104",
  "level": "warning",
  "message": {
    "text": "Keep TLS certificate verification enabled."
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {
          "uri": "src/status_relay/probes.py"
        },
        "region": {
          "startLine": 26
        }
      }
    }
  ]
}
```

## Reproduce the scan locally

Use Git and Python 3.10 or later in an activated virtual environment. Run the
two scans against the same base commit. Use fresh report filenames if you have
run the commands before.

```sh
git clone https://github.com/msol3sco/ai-code-guardian-demo.git
cd ai-code-guardian-demo
python -m pip install "git+https://github.com/msol3sco/ai-code-guardian.git@23fdbdc08239e6a62b7214a8281d998768303faf"
ai-code-guardian scan --diff 0506b6e7a166aa832dcb520ad43047b651e9e52c --head 37a241e7451c5af638338a0bc6c23132532abcf4 --format sarif --output before.sarif
ai-code-guardian scan --diff 0506b6e7a166aa832dcb520ad43047b651e9e52c --head 9e6846b5a4876692439db23cc5584e81c8c0bfb3 --format sarif --output after.sarif
```

The first scan should return 1 and report `ACG104` at
`src/status_relay/probes.py:26`. The corrected scan should
return 0. The app's tests use mock responses throughout, and the scanner
makes no requests to the health-check endpoints.
