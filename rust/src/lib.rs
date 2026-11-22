//! Сканер утекших секретов — Rust-порт Python-версии keylens.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Версия, общая для всех реализаций.
pub const VERSION: &str = "0.1.0";

/// Каталоги, которые пропускаются при сканировании.
pub const DEFAULT_EXCLUDE: &[&str] = &[
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__",
    "dist", "build", ".mypy_cache", ".pytest_cache", ".idea", ".vscode",
];

const TEXT_EXT: &[&str] = &[
    "bash", "c", "cfg", "cpp", "css", "cs", "env", "go", "gradle", "h",
    "hpp", "html", "ini", "java", "js", "json", "kt", "md", "php",
    "properties", "py", "rb", "rs", "sh", "sql", "tf", "toml", "ts",
    "txt", "xml", "yaml", "yml",
];

const TEXT_NAMES: &[&str] = &["Dockerfile", "Makefile", ".env", ".gitignore"];

/// Одна находка.
#[derive(Clone, Debug)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub pattern: String,
    pub severity: String,
    pub matched: String,
}

/// Скрывает середину секрета.
pub fn mask(s: &str) -> String {
    if s.len() <= 8 {
        "*".repeat(s.len())
    } else {
        format!("{}...{}", &s[..4], &s[s.len() - 4..])
    }
}

fn is_alnum(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}
fn is_upper_digit(c: u8) -> bool {
    c.is_ascii_uppercase() || c.is_ascii_digit()
}
fn is_word(c: u8) -> bool {
    is_alnum(c) || c == b'_'
}
fn is_secret_char(c: u8) -> bool {
    is_alnum(c) || c == b'-' || c == b'_'
}

fn find_fixed(line: &str, prefix: &str, n: usize, valid: fn(u8) -> bool) -> Vec<String> {
    let b = line.as_bytes();
    let p = prefix.as_bytes();
    let mut out = Vec::new();
    let mut start = 0usize;
    while start < b.len() {
        let mut found = false;
        let mut i = start;
        while i + p.len() <= b.len() {
            if &b[i..i + p.len()] == p {
                let end = i + p.len();
                if end + n <= b.len() && (0..n).all(|k| valid(b[end + k])) {
                    out.push(line[i..end + n].to_string());
                    start = end + n;
                    found = true;
                    break;
                }
            }
            i += 1;
        }
        if !found {
            break;
        }
    }
    out
}

fn find_variable(line: &str, prefix: &str, min: usize, valid: fn(u8) -> bool) -> Vec<String> {
    let b = line.as_bytes();
    let p = prefix.as_bytes();
    let mut out = Vec::new();
    let mut start = 0usize;
    while start < b.len() {
        let mut found = false;
        let mut i = start;
        while i + p.len() <= b.len() {
            if &b[i..i + p.len()] == p {
                let mut end = i + p.len();
                while end < b.len() && valid(b[end]) {
                    end += 1;
                }
                if end - i - p.len() >= min {
                    out.push(line[i..end].to_string());
                    start = end;
                    found = true;
                    break;
                }
            }
            i += 1;
        }
        if !found {
            break;
        }
    }
    out
}

fn find_slack(line: &str) -> Vec<String> {
    let b = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 5 <= b.len() {
        if &b[i..i + 3] == b"xox"
            && matches!(b[i + 3], b'b' | b'a' | b'p' | b'r' | b's')
            && b[i + 4] == b'-'
        {
            let mut j = i + 5;
            while j < b.len() && is_secret_char(b[j]) {
                j += 1;
            }
            if j - (i + 5) >= 10 {
                out.push(line[i..j].to_string());
                i = j;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn find_telegram(line: &str) -> Vec<String> {
    let b = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        if !b[i].is_ascii_digit() || i > 0 && is_word(b[i - 1]) {
            i += 1;
            continue;
        }
        let mut j = i;
        while j < b.len() && b[j].is_ascii_digit() && j - i < 10 {
            j += 1;
        }
        if j - i < 8 || j >= b.len() || b[j] != b':' {
            i = j.max(i + 1);
            continue;
        }
        let mut k = j + 1;
        while k < b.len() && is_secret_char(b[k]) {
            k += 1;
        }
        if k - (j + 1) == 35 && (k == b.len() || !is_word(b[k])) {
            out.push(line[i..k].to_string());
            i = k;
        } else {
            i += 1;
        }
    }
    out
}

fn find_pem(line: &str) -> Vec<String> {
    const PREFIXES: &[&str] = &[
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
    ];
    let mut out = Vec::new();
    for p in PREFIXES {
        for (idx, _) in line.match_indices(p) {
            out.push(p.to_string());
            let _ = idx;
        }
    }
    out
}

fn find_assignment(line: &str) -> Vec<String> {
    let lower = line.to_ascii_lowercase();
    let lb = lower.as_bytes();
    let b = line.as_bytes();
    let mut out = Vec::new();
    for key in ["api_key", "apikey", "api-key", "secret", "token"] {
        let k = key.as_bytes();
        let mut start = 0usize;
        while start + k.len() <= b.len() {
            let mut found = false;
            let mut i = start;
            while i + k.len() <= b.len() {
                if &lb[i..i + k.len()] == k {
                    let mut j = i + k.len();
                    while j < b.len() && (b[j] == b' ' || b[j] == b'\t') {
                        j += 1;
                    }
                    if j < b.len() && (b[j] == b':' || b[j] == b'=') {
                        j += 1;
                        while j < b.len() && (b[j] == b' ' || b[j] == b'\t') {
                            j += 1;
                        }
                        if j < b.len() && (b[j] == b'\'' || b[j] == b'"') {
                            let quote = b[j];
                            j += 1;
                            let begin = j;
                            while j < b.len() && is_secret_char(b[j]) {
                                j += 1;
                            }
                            if j - begin >= 16 && j < b.len() && b[j] == quote {
                                out.push(line[begin..j].to_string());
                                start = j;
                                found = true;
                                break;
                            }
                        }
                    }
                }
                i += 1;
            }
            if !found {
                break;
            }
        }
    }
    out
}

fn github_classic(l: &str) -> Vec<String> {
    find_fixed(l, "ghp_", 36, is_alnum)
}
fn github_fine(l: &str) -> Vec<String> {
    find_variable(l, "github_pat_", 60, is_secret_char)
}
fn github_oauth(l: &str) -> Vec<String> {
    find_fixed(l, "gho_", 36, is_alnum)
}
fn aws_key(l: &str) -> Vec<String> {
    find_fixed(l, "AKIA", 16, is_upper_digit)
}
fn openai_key(l: &str) -> Vec<String> {
    find_variable(l, "sk-", 20, is_alnum)
}

type Finder = fn(&str) -> Vec<String>;
const RULES: &[(&str, &str, Finder)] = &[
    ("GitHub PAT (classic)", "high", github_classic),
    ("GitHub PAT (fine-grained)", "high", github_fine),
    ("GitHub OAuth token", "high", github_oauth),
    ("AWS Access Key ID", "high", aws_key),
    ("Slack token", "high", find_slack),
    ("OpenAI API key", "high", openai_key),
    ("Telegram bot token", "high", find_telegram),
    ("Private key", "high", find_pem),
    ("Secret assignment", "medium", find_assignment),
];

fn is_text_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if TEXT_NAMES.contains(&name) {
        return true;
    }
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    TEXT_EXT.contains(&ext.as_str())
}

/// Сканирует один файл.
pub fn scan_file(path: &Path, root: &Path) -> Vec<Finding> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    let normalized = text.replace("\r\n", "\n");
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for (idx, line) in normalized.split('\n').enumerate() {
        let mut known: Vec<String> = Vec::new();
        for (name, severity, finder) in RULES {
            for value in finder(line) {
                let key = format!("{}\0{}\0{}", name, idx + 1, value);
                if seen.contains(&key) {
                    continue;
                }
                if *severity == "medium"
                    && known.iter().any(|k| k.contains(&value) || value.contains(k))
                {
                    continue;
                }
                seen.insert(key);
                known.push(value.clone());
                out.push(Finding {
                    file: rel.clone(),
                    line: idx + 1,
                    pattern: (*name).to_string(),
                    severity: (*severity).to_string(),
                    matched: mask(&value),
                });
            }
        }
    }
    out
}

fn walk(dir: &Path, excluded: &[String], files: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if excluded.iter().any(|x| x == name) {
                    continue;
                }
            }
            walk(&path, excluded, files);
        } else {
            files.push(path);
        }
    }
}

/// Сканирует путь, возвращая находки и количество просмотренных файлов.
pub fn scan_path(
    target: &str,
    extras: &[String],
    max_bytes: u64,
) -> Result<(Vec<Finding>, usize), String> {
    let p = Path::new(target);
    let md = fs::metadata(p).map_err(|_| format!("путь не найден: {}", target))?;
    let mut excluded: Vec<String> = DEFAULT_EXCLUDE.iter().map(|s| s.to_string()).collect();
    excluded.extend(extras.iter().cloned());

    let mut files = Vec::new();
    let root = if md.is_dir() {
        p.to_path_buf()
    } else {
        p.parent().unwrap_or(Path::new(".")).to_path_buf()
    };
    if md.is_dir() {
        walk(p, &excluded, &mut files);
    } else {
        files.push(p.to_path_buf());
    }

    let mut out = Vec::new();
    let mut scanned = 0usize;
    for f in files {
        if !is_text_file(&f) {
            continue;
        }
        match fs::metadata(&f) {
            Ok(m) if m.len() <= max_bytes => {}
            _ => continue,
        }
        scanned += 1;
        out.extend(scan_file(&f, &root));
    }
    Ok((out, scanned))
}

fn escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 32 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Сериализует находки в JSON (без внешних зависимостей).
pub fn to_json(items: &[Finding]) -> String {
    let mut out = String::from("[\n");
    for (i, f) in items.iter().enumerate() {
        out.push_str("  {\n");
        out.push_str(&format!("    \"file\": \"{}\",\n", escape(&f.file)));
        out.push_str(&format!("    \"line\": {},\n", f.line));
        out.push_str(&format!("    \"pattern\": \"{}\",\n", escape(&f.pattern)));
        out.push_str(&format!("    \"severity\": \"{}\",\n", escape(&f.severity)));
        out.push_str(&format!("    \"match\": \"{}\"\n", escape(&f.matched)));
        out.push_str("  }");
        if i + 1 < items.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push(']');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask() {
        assert_eq!(mask("short"), "*****");
        assert_eq!(
            mask("ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
            "ghp_...6789"
        );
    }

    #[test]
    fn test_rules() {
        let cases = [
            ("GitHub PAT (classic)", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
            ("AWS Access Key ID", "AKIAABCDEFGHIJKLMNOP"),
            ("Slack token", "xoxb-123456789012-abcdef"),
            ("OpenAI API key", "sk-abcdefghijklmnopqrstuvwx"),
            ("Private key", "-----BEGIN RSA PRIVATE KEY-----"),
        ];
        for (name, expected) in cases {
            let mut found = false;
            for (n, _, finder) in RULES {
                if *n == name && finder(expected).iter().any(|v| v == expected) {
                    found = true;
                }
            }
            assert!(found, "{}: не найдено {:?}", name, expected);
        }
        assert!(find_assignment("api_key = \"abcdefghijklmnop\"").contains(&"abcdefghijklmnop".to_string()));
    }

    #[test]
    fn test_scan_path() {
        let dir = std::env::temp_dir().join(format!("keylens-rust-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join(".git")).unwrap();
        fs::write(
            dir.join("config.py"),
            "key = \"ghp_abcdefghijklmnopqrstuvwxyz0123456789\"\n",
        )
        .unwrap();
        fs::write(dir.join("notes.md"), "api_key = \"abcdefghijklmnop\"\n").unwrap();
        fs::write(
            dir.join(".git/config"),
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789\n",
        )
        .unwrap();

        let (findings, scanned) = scan_path(dir.to_str().unwrap(), &[], 2 << 20).unwrap();
        assert!(scanned >= 2);
        assert_eq!(findings.len(), 2, "{:?}", findings);
        assert!(findings.iter().all(|f| !f.file.contains(".git/")));
        fs::remove_dir_all(dir).unwrap();
    }
}
