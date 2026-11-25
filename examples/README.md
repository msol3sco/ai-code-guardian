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
Code Guardian. The example preserves the SARIF file as an Actions artifact.
