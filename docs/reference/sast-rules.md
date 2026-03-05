# SAST Rules Reference

SAST runs automatically when `oxide-ci scan` encounters a `.js`, `.jsx`, `.ts`, or `.tsx` file. It uses tree-sitter to parse the file into an AST before running any checks.

## Dangerous pattern rules

These rules fire on specific API calls regardless of whether arguments are string literals:

| Rule ID | What it flags |
|---|---|
| `SAST/DangerouslySetInnerHTML` | `<div dangerouslySetInnerHTML={{__html: ...}} />` in TSX/JSX |
| `SAST/InnerHTMLAssignment` | `element.innerHTML = expr` |
| `SAST/OuterHTMLAssignment` | `element.outerHTML = expr` |
| `SAST/EvalUsage` | `eval(expr)` |
| `SAST/FunctionConstructor` | `new Function(...)` |
| `SAST/SetTimeoutString` | `setTimeout("code", delay)` — string as first argument |
| `SAST/SetIntervalString` | `setInterval("code", delay)` — string as first argument |
| `SAST/ChildProcessExec` | `child_process.exec(cmd)` |
| `SAST/ChildProcessExecSync` | `child_process.execSync(cmd)` |
| `SAST/ChildProcessSpawn` | `child_process.spawn(cmd, args)` |
| `SAST/ChildProcessExecFile` | `child_process.execFile(cmd)` |
| `SAST/DocumentWrite` | `document.write(expr)` |
| `SAST/DocumentWriteln` | `document.writeln(expr)` |

## Code smell rules

| Rule ID | Trigger | Default threshold |
|---|---|---|
| `SMELL/LongFunction` | Function body exceeds N lines | 50 lines |
| `SMELL/TooManyParameters` | Function has more than N parameters | 5 params |
| `SMELL/DeepNesting` | Control-flow depth exceeds N levels inside a function | 4 levels |

Rule IDs embed the measured value — e.g. `SMELL/LongFunction (63 lines, max 50)` — for immediate context. Thresholds are configurable in `.oxideci.toml`.

## Custom rules

Define project-specific rules using [tree-sitter S-expression queries](https://tree-sitter.github.io/tree-sitter/using-parsers/queries/). Each rule must include a `@match` capture marking the outermost node to report:

```toml
[sast]
custom_rules = [
  { id = "CUSTOM/EvalCall", query = "(call_expression function: (identifier) @_fn (#eq? @_fn \"eval\") arguments: (_) @match)" },
  { id = "CUSTOM/FetchCall", query = "(call_expression function: (identifier) @_fn (#eq? @_fn \"fetch\") @match)" },
]
```

Custom rules are validated at startup — invalid queries are skipped with a warning and never cause oxide-ci to crash.

## Disabling rules

```toml
[sast]
disabled_rules = [
  "SAST/ChildProcessExec",
  "SAST/DocumentWrite",
  "SMELL/LongFunction",
]
```

Or disable SAST entirely:

```toml
[sast]
enabled = false
```
