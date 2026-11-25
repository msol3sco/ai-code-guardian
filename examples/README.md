# Try changed-lines scanning

Use a scratch Git repository and ensure your Git author identity is configured
before committing. Start with `review.py` containing:

```python
import requests

def load_page(url):
    return requests.get(url, timeout=5)
```

Stage and commit it. Then add a line containing `verify=False` as a keyword
argument to the call:

```python
import requests

def load_page(url):
    return requests.get(
        url,
        timeout=5,
        verify=False,
    )
```

Run `git add review.py` and `ai-code-guardian scan --staged`. The report will
flag the changed call for TLS verification. Restore certificate verification,
stage the correction, and rerun the command to verify the fix.

For CI, use the [workflow example](guardian.yml) with a trusted commit of AI
Code Guardian 1.1.0 or newer. The example preserves the SARIF file as an
Actions artifact and emits file-and-line annotations on pull requests.

## Verify annotations on GitHub

After enabling the workflow, create a throwaway branch containing the TLS
example above and open a pull request against the default branch. The
Guardian job should annotate the `verify=False` line in the pull request
**Checks** tab and fail with exit code 1. Download `guardian-sarif` from
the workflow run to view the full result. Restore certificate verification
and push the correction, or close the test pull request.

To try repository settings, see the [example policy](policy.json) and
the [policy reference](../docs/policy.md).
