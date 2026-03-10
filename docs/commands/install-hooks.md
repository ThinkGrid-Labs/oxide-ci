# install-hooks — Git Pre-commit Hook

Installs greengate as a Git pre-commit hook. After installation, `greengate scan --staged` runs automatically on every `git commit`, blocking the commit if secrets or SAST issues are found.

## Usage

```
greengate install-hooks
```

No options. Run from the root of a Git repository.

## What it does

Writes `.git/hooks/pre-commit` with:

```bash
#!/bin/sh
greengate scan --staged
```

This scans only the files staged for the current commit (`git diff --cached`), so it's fast even on large repositories.

## Uninstalling

Delete the hook file:

```bash
rm .git/hooks/pre-commit
```

## Suppressing a specific commit

To bypass the hook for a single commit (use sparingly):

```bash
git commit --no-verify
```
