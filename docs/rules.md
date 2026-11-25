# Detection rules

| ID | Rule | Evidence line |
| --- | --- | --- |
| ACG001 | Private key marker in UTF-8 text | Marker line |
| ACG002 | Selected GitHub, AWS, Slack, OpenAI, or Stripe credential format | Token line |
| ACG003 | Possible literal credential assigned to a recognizable field name | Assignment line |
| ACG101 | Python `eval` or `exec` | Call line |
| ACG102 | Python `os.system`, `os.popen`, or a supported `subprocess` call with literal `shell=True` | Call or literal flag line |
| ACG103 | Python `pickle.load` or `pickle.loads` (also `_pickle`) | Call line |
| ACG104 | Supported Python `requests` call with literal `verify=False` | Call or literal flag line |
| ACG201 | Known PyPI advisory for an explicitly pinned package | Requirements line |

For a flagged call with a literal keyword on a separate line, changed-lines mode
points to the keyword value if that line changed. If only the call line changed,
it points there instead. Source rules report each rule at most once per line.
An advisory yields an individual dependency finding.

Generic assignments recognize quoted values and also unquoted values in
filenames beginning with `.env`. The heuristic filters out short, simple, and
obvious placeholder values. Credential formats are checked locally and may
match fabricated examples or historical values.

The Python checks recognize a small set of direct and aliased imports. They do
not model Python scope or runtime rebinding and cannot infer dynamic values,
data flow, or call reachability. Secret scanning still runs when Python cannot
be parsed by the interpreter in use.
