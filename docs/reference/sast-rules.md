# SAST Rules Reference

SAST runs automatically when `oxide-ci scan` encounters a supported source file. It uses tree-sitter to parse each file into a real AST before running any checks.

**Supported languages:**

| Language | Extensions | Features |
|---|---|---|
| JavaScript | `.js`, `.jsx` | String-literal scoping, dangerous patterns, code smells |
| TypeScript | `.ts`, `.tsx` | String-literal scoping, dangerous patterns, code smells |
| Python | `.py` | String-literal scoping, dangerous patterns |
| Go | `.go` | String-literal scoping, dangerous patterns |

## Dangerous pattern rules

These rules fire on specific API calls regardless of whether arguments are string literals:

| Rule ID | What it flags |
|---|---|
| `SAST/DangerouslySetInnerHTML` | `dangerouslySetInnerHTML` prop with `__html` value in TSX/JSX |
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

## Python rules

| Rule ID | What it flags | Severity |
|---|---|---|
| `SAST/PythonEval` | `eval(expr)` — arbitrary code execution | critical |
| `SAST/PythonExec` | `exec(code)` — arbitrary code execution | critical |
| `SAST/PythonPickle` | `pickle.load(f)` / `pickle.loads(data)` — unsafe deserialization | high |
| `SAST/PythonSubprocessShell` | Any call with `shell=True` keyword argument — command injection | high |
| `SAST/PythonYamlLoad` | `yaml.load(data)` without a `Loader=` — use `yaml.safe_load` instead | high |

## Go rules

| Rule ID | What it flags | Severity |
|---|---|---|
| `SAST/GoUnsafe` | `import "unsafe"` — direct memory manipulation bypasses type safety | high |
| `SAST/GoExecCommand` | `exec.Command(cmd, ...)` — possible command injection | high |
| `SAST/GoPanic` | `panic(...)` — unexpected process termination in production code | medium |

## Code smell rules

| Rule ID | Trigger | Default threshold |
|---|---|---|
| `SMELL/LongFunction` | Function body exceeds N lines | 50 lines |
| `SMELL/TooManyParameters` | Function has more than N parameters | 5 params |
| `SMELL/DeepNesting` | Control-flow depth exceeds N levels inside a function | 4 levels |

Rule IDs embed the measured value — e.g. `SMELL/LongFunction (63 lines, max 50)` — for immediate context. Thresholds are configurable in `.oxideci.toml`.

## Suppressing findings in Python / Go

Use a same-line comment to suppress a specific finding:

```python
data = pickle.load(f)  # oxide-ci: ignore
```

```go
panic("fatal: unrecoverable state")  // oxide-ci: ignore
```

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
