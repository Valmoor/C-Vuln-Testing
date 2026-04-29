# vuln-c-app

> ⚠️ **FOR SECURITY TESTING ONLY** — This repository contains **intentional vulnerabilities** for evaluating AppSec tools. Do NOT deploy to production.

## Vulnerabilities Included

| File | Vulnerability | CWE |
|------|--------------|-----|
| src/main.c | Buffer overflow via `strcpy` | CWE-120 |
| src/main.c | Format string injection | CWE-134 |
| src/main.c | Command injection via `system()` | CWE-78 |
| src/main.c | Use of `gets()` | CWE-242 |
| src/main.c | Integer overflow in allocation | CWE-190 |
| src/main.c | Use-after-free | CWE-416 |
| src/main.c | Null pointer dereference | CWE-476 |
| src/main.c | Path traversal | CWE-22 |
| src/main.c | Hardcoded credentials & API key | CWE-798 |
| src/main.c | Insecure PRNG (fixed seed) | CWE-338 |
| src/server.c | Stack overflow via `recv()` | CWE-120 |
| src/server.c | Hardcoded AWS keys & DB conn string | CWE-798 |
| src/server.c | Information disclosure in errors | CWE-209 |
| src/server.c | TOCTOU race condition | CWE-362 |
| src/server.c | Insecure temp file creation | CWE-377 |
| src/server.c | World-readable file permissions | CWE-732 |

## Build

```bash
make
```
