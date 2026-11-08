# Synthetic demonstration fixture

This value is invented and cannot authenticate to any service. The inline fixture
marker prevents this teaching file from blocking CodeShield's own security gate.
The demo removes that marker only in its disposable copy, where detection must
block. No real credentials belong in this directory.

From the CodeShield checkout after installation:

```sh
python scripts/demo.py
python scripts/demo.py --approve-demo-fix
```

The first command detects, verifies with mock, explains, and previews without
applying a fix. The second explicitly approves the demonstrated fix in a new
temporary repository, proves the original index still blocks, then intentionally
restages and checks the clean index. Both automatically remove their temporary
repository, never touch this checkout's index, and never call Gemini.
