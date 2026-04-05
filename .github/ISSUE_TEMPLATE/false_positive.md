---
name: False positive
about: A finding that should not have been flagged (secret pattern, SAST rule, supply-chain signal, etc.)
labels: false-positive
---

## Command and rule

<!-- Which command produced the finding, and what rule/signal ID was fired? -->
<!-- e.g. `greengate scan` → rule "AWS Access Key", or `greengate watch-install` → SCRIPT_THREAT signal "fetch(" -->

**Command:** `greengate `
**Rule / signal:** 

## The flagged content

<!-- Paste the flagged line or script content. Redact any real secrets. -->

```
<!-- flagged content here -->
```

## Why this is a false positive

<!-- Explain why this should not have been flagged. -->

## Suggested fix

<!-- Optional: how should the rule/pattern/signal be tightened? -->
