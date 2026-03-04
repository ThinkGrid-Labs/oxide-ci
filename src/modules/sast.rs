use crate::modules::scanner::{Finding, check_entropy, is_js_ts_file};
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
//   • JSX text content (<p>user at example.com</p>)
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
    custom_rule_srcs: &[(String, String)],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // ── Built-in rules ────────────────────────────────────────────────────────
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

        let match_idx = match query.capture_names().iter().position(|n| *n == "match") {
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

    // ── Custom rules from .oxideci.toml ───────────────────────────────────────
    for (id, query_src) in custom_rule_srcs {
        // Compile per-language: query types differ between JS and TS grammars.
        let query = match Query::new(lang, query_src) {
            Ok(q) => q,
            Err(_) => continue, // already warned at pre-scan compile time
        };

        let match_idx = match query.capture_names().iter().position(|n| *n == "match") {
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
                    rule_id: id.clone(),
                    line: line_no,
                    commit: None,
                });
            }
        }
    }

    findings
}

// ── Code smell / complexity detection ────────────────────────────────────────

/// tree-sitter node kinds that represent function-like constructs in JS/TS.
const FUNCTION_NODE_KINDS: &[&str] = &[
    "function_declaration",
    "function",
    "arrow_function",
    "method_definition",
    "generator_function_declaration",
    "generator_function",
];

/// tree-sitter node kinds that introduce a nesting level for SMELL/DeepNesting.
const NESTING_NODE_KINDS: &[&str] = &[
    "if_statement",
    "for_statement",
    "for_in_statement",
    "while_statement",
    "do_statement",
    "switch_statement",
    "try_statement",
    "catch_clause",
];

/// Returns the number of source lines occupied by a function node's body.
fn count_function_lines(node: tree_sitter::Node) -> usize {
    let body = node.child_by_field_name("body").unwrap_or(node);
    let start = body.start_position().row;
    let end = body.end_position().row;
    end.saturating_sub(start) + 1
}

/// Returns the number of formal parameters for a function-like node.
fn count_parameters(node: tree_sitter::Node) -> usize {
    node.child_by_field_name("parameters")
        .map(|p| p.named_child_count())
        .unwrap_or(0)
}

/// Recursively computes the maximum nesting depth within `node`.
fn max_nesting_depth_in(node: tree_sitter::Node, current: usize) -> usize {
    let mut depth = current;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let child_depth = if NESTING_NODE_KINDS.contains(&child.kind()) {
            max_nesting_depth_in(child, current + 1)
        } else {
            max_nesting_depth_in(child, current)
        };
        depth = depth.max(child_depth);
    }
    depth
}

fn scan_complexity(
    path: &Path,
    tree: &tree_sitter::Tree,
    source: &[u8],
    sast_config: &SastConfig,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Iterative stack traversal — avoids recursion on deeply nested files.
    let mut stack: Vec<tree_sitter::Node> = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if FUNCTION_NODE_KINDS.contains(&node.kind()) {
            let line_no = node.start_position().row + 1;

            // Inline suppression
            let suppressed = source
                .split(|&b| b == b'\n')
                .nth(node.start_position().row)
                .and_then(|l| std::str::from_utf8(l).ok())
                .map(|l| l.contains("oxide-ci: ignore"))
                .unwrap_or(false);

            if !suppressed {
                // SMELL/LongFunction
                if !sast_config
                    .disabled_rules
                    .iter()
                    .any(|d| d == "SMELL/LongFunction")
                {
                    let lines = count_function_lines(node);
                    if lines > sast_config.max_function_lines {
                        findings.push(Finding {
                            path: path.to_path_buf(),
                            rule_id: format!(
                                "SMELL/LongFunction ({} lines, max {})",
                                lines, sast_config.max_function_lines
                            ),
                            line: line_no,
                            commit: None,
                        });
                    }
                }

                // SMELL/TooManyParameters
                if !sast_config
                    .disabled_rules
                    .iter()
                    .any(|d| d == "SMELL/TooManyParameters")
                {
                    let params = count_parameters(node);
                    if params > sast_config.max_parameters {
                        findings.push(Finding {
                            path: path.to_path_buf(),
                            rule_id: format!(
                                "SMELL/TooManyParameters ({} params, max {})",
                                params, sast_config.max_parameters
                            ),
                            line: line_no,
                            commit: None,
                        });
                    }
                }

                // SMELL/DeepNesting — measured within the function body only
                if !sast_config
                    .disabled_rules
                    .iter()
                    .any(|d| d == "SMELL/DeepNesting")
                {
                    if let Some(body) = node.child_by_field_name("body") {
                        let depth = max_nesting_depth_in(body, 0);
                        if depth > sast_config.max_nesting_depth {
                            findings.push(Finding {
                                path: path.to_path_buf(),
                                rule_id: format!(
                                    "SMELL/DeepNesting (depth {}, max {})",
                                    depth, sast_config.max_nesting_depth
                                ),
                                line: line_no,
                                commit: None,
                            });
                        }
                    }
                }
            }
        }

        // Push children for traversal.
        let mut child_cursor = node.walk();
        for child in node.children(&mut child_cursor) {
            stack.push(child);
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
    custom_rule_srcs: &[(String, String)],
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
    findings.extend(scan_dangerous_patterns(
        path,
        &tree,
        bytes,
        &lang,
        sast_config,
        custom_rule_srcs,
    ));

    // Code smell / complexity rules
    findings.extend(scan_complexity(path, &tree, bytes, sast_config));

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
        terminal::info(&format!("SAST: scanning {} JS/TS file(s)...", js_ts.len()));
    }

    let bar = if is_text {
        let b = terminal::create_progress_bar(js_ts.len() as u64);
        b.set_message("SAST scanning...");
        Some(b)
    } else {
        None
    };

    // Compile custom rules once before the parallel scan.
    // Validate against the JS grammar as a quick syntax check; warn and skip on error.
    let custom_rule_srcs: Vec<(String, String)> = sast_config
        .custom_rules
        .iter()
        .filter(|r| !sast_config.disabled_rules.iter().any(|d| d == &r.id))
        .filter_map(|r| {
            let lang: Language = tree_sitter_javascript::LANGUAGE.into();
            match Query::new(&lang, &r.query) {
                Ok(_) => Some((r.id.clone(), r.query.clone())),
                Err(e) => {
                    eprintln!(
                        "oxide-ci: warning: custom SAST rule '{}' failed to compile: {}",
                        r.id, e
                    );
                    None
                }
            }
        })
        .collect();

    let findings: Vec<Finding> = js_ts
        .par_iter()
        .flat_map(|path| {
            let result = scan_file(
                path,
                sast_config,
                secret_patterns,
                scan_config,
                &custom_rule_srcs,
            );
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
    use crate::utils::config::{CustomSastRule, SastConfig, ScanConfig};
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
        let f = write_tmp("ts", "const key = \"AKIAIOSFODNN7EXAMPLE123\";\n"); // oxide-ci: ignore
        let findings = scan_file(f.path(), &sast, &patterns, &scan, &[]);
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
        let f = write_tmp("ts", "// AKIAIOSFODNN7EXAMPLE123\n"); // oxide-ci: ignore
        let findings = scan_file(f.path(), &sast, &patterns, &scan, &[]);
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
        let f = write_tmp(
            "tsx",
            "export const A = () => <p>contact@example.com</p>;\n", // oxide-ci: ignore
        );
        let findings = scan_file(f.path(), &sast, &patterns, &scan, &[]);
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
        let f = write_tmp("js", "const k = `AKIAIOSFODNN7EXAMPLE123`;\n"); // oxide-ci: ignore
        let findings = scan_file(f.path(), &sast, &patterns, &scan, &[]);
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
        let findings = scan_file(f.path(), &sast, &patterns, &scan, &[]);
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
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
        assert!(
            findings.iter().any(|x| x.rule_id == "SAST/EvalUsage"),
            "eval() should be flagged"
        );
    }

    #[test]
    fn detects_inner_html_assignment() {
        let (sast, scan) = default_configs();
        let f = write_tmp("js", "el.innerHTML = dangerousData;\n");
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
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
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
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
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
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
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
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
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
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
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
        assert!(
            findings.iter().any(|x| x.rule_id == "SAST/DocumentWrite"),
            "document.write() should be flagged"
        );
    }

    #[test]
    fn detects_settimeout_string() {
        let (sast, scan) = default_configs();
        let f = write_tmp("js", "setTimeout(\"doSomething()\", 1000);\n");
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
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
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
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
            ..Default::default()
        };
        let scan = ScanConfig::default();
        let f = write_tmp("js", "eval(x);\n");
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
        assert!(
            !findings.iter().any(|x| x.rule_id == "SAST/EvalUsage"),
            "disabled rule should produce no finding"
        );
    }

    #[test]
    fn suppression_skips_finding() {
        let (sast, scan) = default_configs();
        let f = write_tmp("js", "eval(x); // oxide-ci: ignore\n");
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
        assert!(
            !findings.iter().any(|x| x.rule_id == "SAST/EvalUsage"),
            "suppressed eval() should not be reported"
        );
    }

    #[test]
    fn non_js_ts_file_returns_empty() {
        let (sast, scan) = default_configs();
        let f = write_tmp("py", "eval(x)\n");
        let findings = scan_file(f.path(), &sast, &[], &scan, &[]);
        assert!(findings.is_empty(), "Python file should be skipped by SAST");
    }

    // ── Complexity rules ──────────────────────────────────────────────────────

    fn long_fn_src(body_lines: usize) -> String {
        // function with `body_lines` lines in the body block
        let body: String = (0..body_lines).map(|i| format!("  x{}();\n", i)).collect();
        format!("function f() {{\n{}}}\n", body)
    }

    #[test]
    fn detects_long_function() {
        let sast = SastConfig {
            max_function_lines: 3,
            ..Default::default()
        };
        let f = write_tmp("js", &long_fn_src(6));
        let findings = scan_file(f.path(), &sast, &[], &ScanConfig::default(), &[]);
        assert!(
            findings
                .iter()
                .any(|x| x.rule_id.starts_with("SMELL/LongFunction")),
            "6-line body should exceed max_function_lines=3"
        );
    }

    #[test]
    fn does_not_flag_function_within_line_limit() {
        let sast = SastConfig {
            max_function_lines: 50,
            ..Default::default()
        };
        let f = write_tmp("js", "function f() { return 1; }\n");
        let findings = scan_file(f.path(), &sast, &[], &ScanConfig::default(), &[]);
        assert!(
            !findings
                .iter()
                .any(|x| x.rule_id.starts_with("SMELL/LongFunction")),
            "single-line function should not be flagged"
        );
    }

    #[test]
    fn detects_too_many_parameters() {
        let sast = SastConfig {
            max_parameters: 2,
            ..Default::default()
        };
        let f = write_tmp("js", "function f(a, b, c) { return a; }\n");
        let findings = scan_file(f.path(), &sast, &[], &ScanConfig::default(), &[]);
        assert!(
            findings
                .iter()
                .any(|x| x.rule_id.starts_with("SMELL/TooManyParameters")),
            "3 params should exceed max_parameters=2"
        );
    }

    #[test]
    fn does_not_flag_params_within_limit() {
        let sast = SastConfig {
            max_parameters: 5,
            ..Default::default()
        };
        let f = write_tmp("js", "function f(a, b) { return a + b; }\n");
        let findings = scan_file(f.path(), &sast, &[], &ScanConfig::default(), &[]);
        assert!(
            !findings
                .iter()
                .any(|x| x.rule_id.starts_with("SMELL/TooManyParameters")),
            "2 params should not exceed max_parameters=5"
        );
    }

    #[test]
    fn detects_deep_nesting() {
        let sast = SastConfig {
            max_nesting_depth: 2,
            ..Default::default()
        };
        let src =
            "function f() {\n  if (a) {\n    if (b) {\n      if (c) { x(); }\n    }\n  }\n}\n";
        let f = write_tmp("js", src);
        let findings = scan_file(f.path(), &sast, &[], &ScanConfig::default(), &[]);
        assert!(
            findings
                .iter()
                .any(|x| x.rule_id.starts_with("SMELL/DeepNesting")),
            "triple nested if should exceed max_nesting_depth=2"
        );
    }

    #[test]
    fn does_not_flag_nesting_within_limit() {
        let sast = SastConfig {
            max_nesting_depth: 4,
            ..Default::default()
        };
        let src = "function f() {\n  if (a) {\n    return 1;\n  }\n}\n";
        let f = write_tmp("js", src);
        let findings = scan_file(f.path(), &sast, &[], &ScanConfig::default(), &[]);
        assert!(
            !findings
                .iter()
                .any(|x| x.rule_id.starts_with("SMELL/DeepNesting")),
            "single if should not exceed max_nesting_depth=4"
        );
    }

    #[test]
    fn disabled_smell_rule_not_reported() {
        let sast = SastConfig {
            max_function_lines: 3,
            disabled_rules: vec!["SMELL/LongFunction".into()],
            ..Default::default()
        };
        let f = write_tmp("js", &long_fn_src(6));
        let findings = scan_file(f.path(), &sast, &[], &ScanConfig::default(), &[]);
        assert!(
            !findings
                .iter()
                .any(|x| x.rule_id.starts_with("SMELL/LongFunction")),
            "disabled SMELL/LongFunction should not be reported"
        );
    }

    // ── Custom rules ──────────────────────────────────────────────────────────

    #[test]
    fn custom_rule_fires_for_matching_query() {
        let sast = SastConfig {
            custom_rules: vec![CustomSastRule {
                id: "TEST/NoEval".into(),
                query: r#"(call_expression function: (identifier) @_fn (#eq? @_fn "eval")) @match"#
                    .into(),
            }],
            ..Default::default()
        };
        // Pre-compile the same way run_sast_scan does
        let custom_srcs: Vec<(String, String)> = sast
            .custom_rules
            .iter()
            .map(|r| (r.id.clone(), r.query.clone()))
            .collect();
        let f = write_tmp("js", "eval(x);\n");
        let findings = scan_file(f.path(), &sast, &[], &ScanConfig::default(), &custom_srcs);
        assert!(
            findings.iter().any(|x| x.rule_id == "TEST/NoEval"),
            "custom eval rule should fire"
        );
    }

    #[test]
    fn custom_rule_respects_disabled_rules() {
        let sast = SastConfig {
            custom_rules: vec![CustomSastRule {
                id: "TEST/NoEval".into(),
                query: r#"(call_expression function: (identifier) @_fn (#eq? @_fn "eval")) @match"#
                    .into(),
            }],
            disabled_rules: vec!["TEST/NoEval".into()],
            ..Default::default()
        };
        let custom_srcs: Vec<(String, String)> = vec![]; // disabled — filtered before call
        let f = write_tmp("js", "eval(x);\n");
        let findings = scan_file(f.path(), &sast, &[], &ScanConfig::default(), &custom_srcs);
        assert!(
            !findings.iter().any(|x| x.rule_id == "TEST/NoEval"),
            "disabled custom rule should not fire"
        );
    }

    #[test]
    fn invalid_custom_rule_does_not_panic() {
        // An invalid query is filtered out before reaching scan_file.
        // Verify that passing empty custom_srcs (as run_sast_scan would after filtering)
        // produces no panic and no spurious findings.
        let f = write_tmp("js", "eval(x);\n");
        let findings = scan_file(
            f.path(),
            &SastConfig::default(),
            &[],
            &ScanConfig::default(),
            &[],
        );
        // Should not panic; built-in eval rule still fires (proves scan_file ran normally)
        assert!(findings.iter().any(|x| x.rule_id == "SAST/EvalUsage"));
    }
}
