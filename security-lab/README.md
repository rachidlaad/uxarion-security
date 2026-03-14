Local security regression target for the Codex security fork.

Run:

```bash
python3 /mnt/c/codex-hacker/security-lab/vuln_app.py
```

The app listens on `127.0.0.1:8081`.

Routes:

- `/` shows a search form that submits to `/search`.
- `/search?q=...` reflects the `q` parameter into HTML without escaping.

Intended vulnerability:

- Reflected XSS on `/search`.
