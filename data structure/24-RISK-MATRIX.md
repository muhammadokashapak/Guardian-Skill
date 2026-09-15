# Risk Matrix

| Risk | Impact | Default action |
|---|---|---|
| Exposed secret | Critical | Block/alert, redact |
| Auth bypass | Critical | Human approval |
| Destructive DB action | Critical | Never automatic |
| Production deployment | Critical | Never automatic |
| Security policy weakening | Critical | Never automatic |
| Dependency upgrade | High | Approval + test |
| Auth code modification | High | Approval + verification |
| Normal bug fix | Medium | Controlled approval policy |
| Documentation-only change | Low | May auto-apply if enabled |

Severity is not the same as confidence; both must be tracked.
