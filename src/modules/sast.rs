use crate::modules::scanner::{check_entropy, is_js_ts_file, Finding};
use crate::utils::{
    config::{SastConfig, ScanConfig},
    terminal,
};
use anyhow::Result;
use rayon::prelude::*;
use regex::Regex;
use std::path::{Path, PathBuf};
use streaming_iterator::StreamingIterator;
use tree_sitter::{Language, Parser, Query, QueryCursor};

// ── Language dispatch ─────────────────────────────────────────────────────────

fn language_for(path: &Path) -> Option<Language> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("ts") => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        Some("tsx") => Some(tree_sitter_typescript::LANGUAGE_TSX.into()),
        Some("js" | "jsx") => Some(tree_sitter_javascript::LANGUAGE.into()),
        _ => None,
    }
}

// ── String-literal secret detection ──────────────────────────────────────────
//
// The tree-sitter JS/TS grammar stores string content in `string_fragment`
// child nodes — these contain the raw text, stripped of surrounding quotes
// and escape sequences. Template literal fragments are also `string_fragment`.
//
// Running regex patterns only against `string_fragment` nodes avoids flagging
// secrets mentioned in:
//   • comments  (// or /* */)
//   • JSX text content (<p>example@email.com</p>)
//   • import/export declarations that aren't string values

const STRING_LITERAL_QUERY: &str = r#"
    [
        (string (string_fragment) @literal)
        (template_string (string_fragment) @literal)
    ]
"#;

fn scan_string_literals(
    path: &Path,
    tree: &tree_sitter::Tree,
    source: &[u8],
    lang: &Language,
    patterns: &[(String, Regex)],
    scan_config: &ScanConfig,
) -> Vec<Finding> {
    let query = match Query::new(lang, STRING_LITERAL_QUERY) {
        Ok(q) => q,
        Err(_) => return Vec::new(),
    };

    let literal_idx = match query.capture_names().iter().position(|n| *n == "literal") {
        Some(i) => i as u32,
        None => return Vec::new(),
    };

    let mut cursor = QueryCursor::new();
    let mut findings = Vec::new();
    let mut matches = cursor.matches(&query, tree.root_node(), source);

    while let Some(m) = matches.next() {
        for cap in m.captures.iter().filter(|c| c.index == literal_idx) {
            let node = cap.node;
            let text = match node.utf8_text(source) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let line_no = node.start_position().row + 1; // 1-based

            // Inline suppression on the source line
            let source_line = source
                .split(|&b| b == b'\n')
                .nth(node.start_position().row)
                .and_then(|l| std::str::from_utf8(l).ok())
                .unwrap_or("");
            if source_line.contains("oxide-ci: ignore") {
                continue;
            }

            // Run every secret/PII regex against the string literal value only
            for (name, regex) in patterns {
                if regex.is_match(text) {
                    findings.push(Finding {
                        path: path.to_path_buf(),
                        rule_id: name.clone(),
                        line: line_no,
                        commit: None,
                    });
                }
            }

            // Entropy check on the literal value itself
            for rule_id in check_entropy(text, scan_config) {
                findings.push(Finding {
                    path: path.to_path_buf(),
                    rule_id,
                    line: line_no,
                    commit: None,
                });
            }
        }
    }

    findings
}

// ── Dangerous pattern detection ───────────────────────────────────────────────

struct SastRule {
    id: &'static str,
    /// tree-sitter S-expression query. Must contain a @match capture that
    /// marks the outermost node for location reporting.
    query: &'static str,
}

const RULES: &[SastRule] = &[
    // ── XSS ──────────────────────────────────────────────────────────────────
    SastRule {
        id: "SAST/DangerouslySetInnerHTML",
        // JSX attribute: dangerouslySetInnerHTML={{ __html: ... }}
        // Only compiles successfully against TSX / JSX language grammars.
        // Omit `name:` field specifier — the TSX grammar does not surface it
        // as a queryable named field; match the identifier as a direct child instead.
        query: r#"
            (jsx_attribute
              (_) @_name
              (#eq? @_name "dangerouslySetInnerHTML")) @match
        "#,
    },
    SastRule {
        id: "SAST/InnerHTMLAssignment",
        // elem.innerHTML = expr  (any right-hand side)
        query: r#"
            (assignment_expression
              left: (member_expression
                property: (property_identifier) @_prop
                (#eq? @_prop "innerHTML"))) @match
        "#,
    },
    SastRule {
        id: "SAST/OuterHTMLAssignment",
        // elem.outerHTML = expr
        query: r#"
            (assignment_expression
              left: (member_expression
                property: (property_identifier) @_prop
                (#eq? @_prop "outerHTML"))) @match
        "#,
    },
    // ── Code injection ────────────────────────────────────────────────────────
    SastRule {
        id: "SAST/EvalUsage",
        // eval(...)
        query: r#"
            (call_expression
              function: (identifier) @_fn
              (#eq? @_fn "eval")) @match
        "#,
    },
    SastRule {
        id: "SAST/FunctionConstructor",
        // new Function(...)
        query: r#"
            (new_expression
              constructor: (identifier) @_ctor
              (#eq? @_ctor "Function")) @match
        "#,
    },
    SastRule {
        id: "SAST/SetTimeoutString",
        // setTimeout("code string", delay) — string as first arg is eval-equivalent
        query: r#"
            (call_expression
              function: (identifier) @_fn
              (#eq? @_fn "setTimeout")
              arguments: (arguments . [(string) (template_string)] @_first)) @match
        "#,
    },
    SastRule {
        id: "SAST/SetIntervalString",
        // setInterval("code string", delay)
        query: r#"
            (call_expression
              function: (identifier) @_fn
              (#eq? @_fn "setInterval")
              arguments: (arguments . [(string) (template_string)] @_first)) @match
        "#,
    },
    // ── Command injection ─────────────────────────────────────────────────────
    SastRule {
        id: "SAST/ChildProcessExec",
        // child_process.exec(cmd) / require('child_process').exec(cmd) / etc.
        query: r#"
            (call_expression
              function: (member_expression
                property: (property_identifier) @_fn
                (#eq? @_fn "exec"))) @match
        "#,
    },
    SastRule {
        id: "SAST/ChildProcessExecSync",
        query: r#"
            (call_expression
              function: (member_expression
                property: (property_identifier) @_fn
                (#eq? @_fn "execSync"))) @match
        "#,
    },
    SastRule {
        id: "SAST/ChildProcessSpawn",
        // child_process.spawn(cmd, args)
        query: r#"
            (call_expression
              function: (member_expression
                property: (property_identifier) @_fn
                (#eq? @_fn "spawn"))) @match
        "#,
    },
    SastRule {
        id: "SAST/ChildProcessExecFile",
        query: r#"
            (call_expression
              function: (member_expression
                property: (property_identifier) @_fn
                (#eq? @_fn "execFile"))) @match
        "#,
    },
    // ── Legacy DOM XSS ───────────────────────────────────────────────────────
    SastRule {
        id: "SAST/DocumentWrite",
        // document.write(expr) — inserts raw HTML into the document
        query: r#"
            (call_expression
              function: (member_expression
                object: (identifier) @_obj
                property: (property_identifier) @_prop)
              (#eq? @_obj "document")
              (#eq? @_prop "write")) @match
        "#,
    },
    SastRule {
        id: "SAST/DocumentWriteln",
        query: r#"
            (call_expression
              function: (member_expression
                object: (identifier) @_obj
                property: (property_identifier) @_prop)
              (#eq? @_obj "document")
              (#eq? @_prop "writeln")) @match
        "#,
    },
];

fn scan_dangerous_patterns(
    path: &Path,
    tree: &tree_sitter::Tree,
    source: &[u8],
    lang: &Language,
    sast_config: &SastConfig,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for rule in RULES {
        if sast_config.disabled_rules.iter().any(|d| d == rule.id) {
            continue;
        }

        // Query may fail to compile for rules that use JSX node types against
        // non-TSX/JSX language grammars — silently skip those.
        let query = match Query::new(lang, rule.query) {
            Ok(q) => q,
            Err(_) => continue,
        };

        let match_idx = match query
            .capture_names()
            .iter()
            .position(|n| *n == "match")
        {
            Some(i) => i as u32,
            None => continue,
        };

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);
        while let Some(m) = matches.next() {
            if let Some(cap) = m.captures.iter().find(|c| c.index == match_idx) {
                let line_no = cap.node.start_position().row + 1;

                let source_line = source
                    .split(|&b| b == b'\n')
                    .nth(cap.node.start_position().row)
                    .and_then(|l| std::str::from_utf8(l).ok())
                    .unwrap_or("");
                if source_line.contains("oxide-ci: ignore") {
                    continue;
                }

                findings.push(Finding {
                    path: path.to_path_buf(),
                    rule_id: rule.id.to_string(),
                    line: line_no,
                    commit: None,
                });
            }
        }
    }

    findings
}

// ── Per-file scanner ──────────────────────────────────────────────────────────

fn scan_file(
    path: &Path,
    sast_config: &SastConfig,
    secret_patterns: &[(String, Regex)],
    scan_config: &ScanConfig,
) -> Vec<Finding> {
    let source = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let lang = match language_for(path) {
        Some(l) => l,
        None => return Vec::new(),
    };

    // Parser is !Send — must be created per closure (per file).
    let mut parser = Parser::new();
    if parser.set_language(&lang).is_err() {
        return Vec::new();
    }

    // tree-sitter is error-tolerant; parse() returns None only on hard timeout/cancel.
    let tree = match parser.parse(&source, None) {
        Some(t) => t,
        None => return Vec::new(),
    };

    let bytes = source.as_bytes();
    let mut findings = Vec::new();

    // Secrets/PII scoped to string literals only (no comment noise)
    findings.extend(scan_string_literals(
        path,
        &tree,
        bytes,
        &lang,
        secret_patterns,
        scan_config,
    ));

    // Dangerous API patterns (XSS, code injection, command injection)
    findings.extend(scan_dangerous_patterns(path, &tree, bytes, &lang, sast_config));

    findings
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Run the SAST scan over a pre-built file list (produced by `collect_scan_files`).
/// Filters to JS/TS files only; non-JS/TS files are handled by the regex scanner.
pub fn run_sast_scan(
    files: &[PathBuf],
    sast_config: &SastConfig,
    secret_patterns: &[(String, Regex)],
    scan_config: &ScanConfig,
    is_text: bool,
) -> Result<Vec<Finding>> {
    let js_ts: Vec<&PathBuf> = files.iter().filter(|p| is_js_ts_file(p)).collect();

    if js_ts.is_empty() {
        return Ok(Vec::new());
    }

    if is_text {
        terminal::info(&format!(
            "SAST: scanning {} JS/TS file(s)...",
            js_ts.len()
        ));
    }

    let bar = if is_text {
        let b = terminal::create_progress_bar(js_ts.len() as u64);
        b.set_message("SAST scanning...");
        Some(b)
    } else {
        None
    };

    let findings: Vec<Finding> = js_ts
        .par_iter()
        .flat_map(|path| {
            let result = scan_file(path, sast_config, secret_patterns, scan_config);
            if let Some(b) = &bar {
                b.inc(1);
            }
            result
        })
        .collect();

    if let Some(b) = &bar {
        b.finish_with_message("SAST scan complete.");
    }

    Ok(findings)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::config::{SastConfig, ScanConfig};
    use regex::Regex;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn default_configs() -> (SastConfig, ScanConfig) {
        (SastConfig::default(), ScanConfig::default())
    }

    fn compile_builtins() -> Vec<(String, Regex)> {
        vec![
            (
                "AWS Access Key".into(),
                Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
            ),
            (
                "Generic PII (Email)".into(),
                Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}").unwrap(),
            ),
        ]
    }

    fn write_tmp(ext: &str, content: &str) -> NamedTempFile {
        let mut f = tempfile::Builder::new()
            .suffix(&format!(".{}", ext))
            .tempfile()
            .unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    // ── String literal scoping ────────────────────────────────────────────────

    #[test]
    fn detects_aws_key_in_string_literal() {
        let (sast, scan) = default_configs();
        let patterns = compile_builtins();
        let f = write_tmp("ts", "const key = \"AKIAIOSFODNN7EXAMPLE123\";\n");
        let findings = scan_file(f.path(), &sast, &patterns, &scan);
        assert!(
            findings.iter().any(|x| x.rule_id == "AWS Access Key"),
            "expected AWS Access Key in string literal, got: {:?}",
            findings.iter().map(|x| &x.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn ignores_aws_key_in_comment() {
        let (sast, scan) = default_configs();
        let patterns = compile_builtins();
        let f = write_tmp("ts", "// AKIAIOSFODNN7EXAMPLE123\n");
        let findings = scan_file(f.path(), &sast, &patterns, &scan);
        assert!(
            findings.is_empty(),
            "comment-only secret should not be flagged, got: {:?}",
            findings.iter().map(|x| &x.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn ignores_email_in_jsx_text() {
        let (sast, scan) = default_configs();
        let patterns = compile_builtins();
        let f = write_tmp("tsx", "export const A = () => <p>contact@example.com</p>;\n");
        let findings = scan_file(f.path(), &sast, &patterns, &scan);
        let email_hits: Vec<_> = findings
            .iter()
            .filter(|x| x.rule_id.contains("Email"))
            .collect();
        assert!(
            email_hits.is_empty(),
            "email in JSX text content should not be flagged, got: {:?}",
            email_hits.iter().map(|x| &x.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn detects_secret_in_template_literal() {
        let (sast, scan) = default_configs();
        let patterns = compile_builtins();
        let f = write_tmp("js", "const k = `AKIAIOSFODNN7EXAMPLE123`;\n");
        let findings = scan_file(f.path(), &sast, &patterns, &scan);
        assert!(
            findings.iter().any(|x| x.rule_id == "AWS Access Key"),
            "should detect key inside template literal"
        );
    }

    #[test]
    fn respects_inline_suppression() {
        let (sast, scan) = default_configs();
        let patterns = compile_builtins();
        let f = write_tmp(
            "ts",
            "const k = \"AKIAIOSFODNN7EXAMPLE123\"; // oxide-ci: ignore\n",
        );
        let findings = scan_file(f.path(), &sast, &patterns, &scan);
        assert!(
            findings.is_empty(),
            "suppressed line should produce no findings"
        );
    }

    // ── Dangerous patterns ────────────────────────────────────────────────────

    #[test]
    fn detects_eval() {
        let (sast, scan) = default_configs();
        let f = write_tmp("js", "eval(userInput);\n");
        let findings = scan_file(f.path(), &sast, &[], &scan);
        assert!(
            findings.iter().any(|x| x.rule_id == "SAST/EvalUsage"),
            "eval() should be flagged"
        );
    }

    #[test]
    fn detects_inner_html_assignment() {
        let (sast, scan) = default_configs();
        let f = write_tmp("js", "el.innerHTML = dangerousData;\n");
        let findings = scan_file(f.path(), &sast, &[], &scan);
        assert!(
            findings
                .iter()
                .any(|x| x.rule_id == "SAST/InnerHTMLAssignment"),
            "innerHTML assignment should be flagged"
        );
    }

    #[test]
    fn detects_dangerously_set_inner_html() {
        let (sast, scan) = default_configs();
        let f = write_tmp(
            "tsx",
            "export const C = ({v}: {v:string}) => <div dangerouslySetInnerHTML={{__html: v}} />;\n",
        );
        let findings = scan_file(f.path(), &sast, &[], &scan);
        assert!(
            findings
                .iter()
                .any(|x| x.rule_id == "SAST/DangerouslySetInnerHTML"),
            "dangerouslySetInnerHTML should be flagged in TSX"
        );
    }

    #[test]
    fn detects_new_function() {
        let (sast, scan) = default_configs();
        let f = write_tmp("js", "const fn = new Function(\"return 1\");\n");
        let findings = scan_file(f.path(), &sast, &[], &scan);
        assert!(
            findings
                .iter()
                .any(|x| x.rule_id == "SAST/FunctionConstructor"),
            "new Function() should be flagged"
        );
    }

    #[test]
    fn detects_child_process_exec() {
        let (sast, scan) = default_configs();
        let f = write_tmp("js", "child_process.exec(cmd, callback);\n");
        let findings = scan_file(f.path(), &sast, &[], &scan);
        assert!(
            findings
                .iter()
                .any(|x| x.rule_id == "SAST/ChildProcessExec"),
            "child_process.exec() should be flagged"
        );
    }

    #[test]
    fn detects_child_process_spawn() {
        let (sast, scan) = default_configs();
        let f = write_tmp("js", "child_process.spawn(\"bash\", [\"-c\", cmd]);\n");
        let findings = scan_file(f.path(), &sast, &[], &scan);
        assert!(
            findings
                .iter()
                .any(|x| x.rule_id == "SAST/ChildProcessSpawn"),
            "child_process.spawn() should be flagged"
        );
    }

    #[test]
    fn detects_document_write() {
        let (sast, scan) = default_configs();
        let f = write_tmp("js", "document.write(\"<script>\" + userInput);\n");
        let findings = scan_file(f.path(), &sast, &[], &scan);
        assert!(
            findings.iter().any(|x| x.rule_id == "SAST/DocumentWrite"),
            "document.write() should be flagged"
        );
    }

    #[test]
    fn detects_settimeout_string() {
        let (sast, scan) = default_configs();
        let f = write_tmp("js", "setTimeout(\"doSomething()\", 1000);\n");
        let findings = scan_file(f.path(), &sast, &[], &scan);
        assert!(
            findings
                .iter()
                .any(|x| x.rule_id == "SAST/SetTimeoutString"),
            "setTimeout with string arg should be flagged"
        );
    }

    #[test]
    fn does_not_flag_settimeout_with_function() {
        let (sast, scan) = default_configs();
        let f = write_tmp("js", "setTimeout(() => doSomething(), 1000);\n");
        let findings = scan_file(f.path(), &sast, &[], &scan);
        assert!(
            !findings
                .iter()
                .any(|x| x.rule_id == "SAST/SetTimeoutString"),
            "setTimeout with arrow function should NOT be flagged"
        );
    }

    #[test]
    fn disabled_rule_not_reported() {
        let sast = SastConfig {
            enabled: true,
            disabled_rules: vec!["SAST/EvalUsage".into()],
        };
        let scan = ScanConfig::default();
        let f = write_tmp("js", "eval(x);\n");
        let findings = scan_file(f.path(), &sast, &[], &scan);
        assert!(
            !findings.iter().any(|x| x.rule_id == "SAST/EvalUsage"),
            "disabled rule should produce no finding"
        );
    }

    #[test]
    fn suppression_skips_finding() {
        let (sast, scan) = default_configs();
        let f = write_tmp("js", "eval(x); // oxide-ci: ignore\n");
        let findings = scan_file(f.path(), &sast, &[], &scan);
        assert!(
            !findings.iter().any(|x| x.rule_id == "SAST/EvalUsage"),
            "suppressed eval() should not be reported"
        );
    }

    #[test]
    fn non_js_ts_file_returns_empty() {
        let (sast, scan) = default_configs();
        let f = write_tmp("py", "eval(x)\n");
        let findings = scan_file(f.path(), &sast, &[], &scan);
        assert!(findings.is_empty(), "Python file should be skipped by SAST");
    }
}
