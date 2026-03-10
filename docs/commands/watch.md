# watch

Re-runs the secret and SAST scan automatically whenever source files change. Useful for catching secrets during active development without having to run `greengate scan` manually.

## Usage

```bash
greengate watch [--staged] [--interval <ms>]
```

## Options

| Flag | Default | Description |
|---|---|---|
| `--staged` | off | Only scan git-staged files on each change |
| `--interval` | `2000` | Poll interval in milliseconds |

## How it works

`greengate watch` polls the working directory every `--interval` milliseconds. When it detects a file with a newer modification time than the last snapshot, it immediately re-runs the scan and prints results. It then continues watching.

Unlike a watcher that fails the process on findings, `watch` **does not exit on findings** — it reports them and keeps going so you can fix them in-place.

## Examples

```bash
# Watch for changes, scan full working tree
greengate watch

# Watch only staged files (faster in large repos)
greengate watch --staged

# Poll every 500ms for a faster feedback loop
greengate watch --interval 500
```

## Typical local workflow

```bash
# Terminal 1: start watching
greengate watch

# Terminal 2: edit your code
# Every time you save, the scanner re-runs and reports instantly
```

## Notes

- `watch` respects `.gitignore` and `.greengate.toml` exclusion rules
- Ctrl-C stops the watcher
- This command is for local development only — use `greengate scan` in CI
