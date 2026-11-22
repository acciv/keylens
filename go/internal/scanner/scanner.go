// Package scanner находит потенциально утекшие секреты в текстовых файлах.
package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Finding — одна находка.
type Finding struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Pattern  string `json:"pattern"`
	Severity string `json:"severity"`
	Match    string `json:"match"`
}

// MarshalJSONArray используется CLI для вывода в формате JSON.
func MarshalJSONArray(items []Finding) (string, error) {
	b, err := json.MarshalIndent(items, "", "  ")
	return string(b), err
}

// Mask скрывает середину секрета.
func Mask(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + "..." + s[len(s)-4:]
}

var DefaultExclude = []string{
	".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__",
	"dist", "build", ".mypy_cache", ".pytest_cache", ".idea", ".vscode",
}

var textExt = map[string]bool{
	".bash": true, ".c": true, ".cfg": true, ".cpp": true, ".css": true,
	".cs": true, ".env": true, ".go": true, ".gradle": true, ".h": true,
	".hpp": true, ".html": true, ".ini": true, ".java": true, ".js": true,
	".json": true, ".kt": true, ".md": true, ".php": true, ".properties": true,
	".py": true, ".rb": true, ".rs": true, ".sh": true, ".sql": true,
	".tf": true, ".toml": true, ".ts": true, ".txt": true, ".xml": true,
	".yaml": true, ".yml": true,
}

var textNames = map[string]bool{
	"Dockerfile": true, "Makefile": true, ".env": true, ".gitignore": true,
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func isUpperDigit(c byte) bool { return c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' }
func isWord(c byte) bool       { return isAlnum(c) || c == '_' }
func isSecretChar(c byte) bool { return isAlnum(c) || c == '-' || c == '_' }

func findFixed(line, prefix string, n int, valid func(byte) bool) []string {
	var out []string
	for start := 0; start <= len(line)-len(prefix); {
		i := strings.Index(line[start:], prefix)
		if i < 0 {
			break
		}
		pos := start + i
		end := pos + len(prefix)
		if end+n <= len(line) {
			ok := true
			for j := 0; j < n; j++ {
				if !valid(line[end+j]) {
					ok = false
					break
				}
			}
			if ok {
				out = append(out, line[pos:end+n])
				start = end + n
				continue
			}
		}
		start = pos + 1
	}
	return out
}

func findVariable(line, prefix string, min int, valid func(byte) bool) []string {
	var out []string
	for start := 0; start <= len(line)-len(prefix); {
		i := strings.Index(line[start:], prefix)
		if i < 0 {
			break
		}
		pos := start + i
		end := pos + len(prefix)
		for end < len(line) && valid(line[end]) {
			end++
		}
		if end-pos-len(prefix) >= min {
			out = append(out, line[pos:end])
			start = end
			continue
		}
		start = pos + 1
	}
	return out
}

func findTelegram(line string) []string {
	var out []string
	for i := 0; i < len(line); i++ {
		if line[i] < '0' || line[i] > '9' || i > 0 && isWord(line[i-1]) {
			continue
		}
		j := i
		for j < len(line) && line[j] >= '0' && line[j] <= '9' && j-i < 10 {
			j++
		}
		if j-i < 8 || j >= len(line) || line[j] != ':' {
			i = j - 1
			continue
		}
		k := j + 1
		for k < len(line) && isSecretChar(line[k]) {
			k++
		}
		if k-(j+1) == 35 && (k == len(line) || !isWord(line[k])) {
			out = append(out, line[i:k])
			i = k - 1
		}
	}
	return out
}

func findSlack(line string) []string {
	var out []string
	for i := 0; i+5 <= len(line); i++ {
		if line[i:i+3] != "xox" || !strings.ContainsRune("baprs", rune(line[i+3])) || line[i+4] != '-' {
			continue
		}
		j := i + 5
		for j < len(line) && isSecretChar(line[j]) {
			j++
		}
		if j-(i+5) >= 10 {
			out = append(out, line[i:j])
			i = j - 1
		}
	}
	return out
}

func findPEM(line string) []string {
	prefixes := []string{
		"-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----",
		"-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN DSA PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY-----",
	}
	var out []string
	for _, p := range prefixes {
		for start := 0; start <= len(line)-len(p); {
			i := strings.Index(line[start:], p)
			if i < 0 {
				break
			}
			out = append(out, p)
			start = start + i + len(p)
		}
	}
	return out
}

func findAssignment(line string) []string {
	lower := strings.ToLower(line)
	var out []string
	for _, key := range []string{"api_key", "apikey", "api-key", "secret", "token"} {
		for start := 0; start <= len(line)-len(key); {
			i := strings.Index(lower[start:], key)
			if i < 0 {
				break
			}
			pos := start + i
			j := pos + len(key)
			for j < len(line) && (line[j] == ' ' || line[j] == '\t') {
				j++
			}
			if j >= len(line) || line[j] != ':' && line[j] != '=' {
				start = pos + 1
				continue
			}
			j++
			for j < len(line) && (line[j] == ' ' || line[j] == '\t') {
				j++
			}
			if j >= len(line) || line[j] != '\'' && line[j] != '"' {
				start = pos + 1
				continue
			}
			quote := line[j]
			j++
			begin := j
			for j < len(line) && isSecretChar(line[j]) {
				j++
			}
			if j-begin >= 16 && j < len(line) && line[j] == quote {
				out = append(out, line[begin:j])
				start = j
				continue
			}
			start = pos + 1
		}
	}
	return out
}

type rule struct {
	name     string
	severity string
	find     func(string) []string
}

var rules = []rule{
	{"GitHub PAT (classic)", "high", func(l string) []string { return findFixed(l, "ghp_", 36, isAlnum) }},
	{"GitHub PAT (fine-grained)", "high", func(l string) []string {
		return findVariable(l, "github_pat_", 60, isSecretChar)
	}},
	{"GitHub OAuth token", "high", func(l string) []string { return findFixed(l, "gho_", 36, isAlnum) }},
	{"AWS Access Key ID", "high", func(l string) []string { return findFixed(l, "AKIA", 16, isUpperDigit) }},
	{"Slack token", "high", findSlack},
	{"OpenAI API key", "high", func(l string) []string { return findVariable(l, "sk-", 20, isAlnum) }},
	{"Telegram bot token", "high", findTelegram},
	{"Private key", "high", findPEM},
	{"Secret assignment", "medium", findAssignment},
}

func isTextFile(path string) bool {
	base := filepath.Base(path)
	return textNames[base] || textExt[strings.ToLower(filepath.Ext(path))]
}

// ScanFile сканирует один файл.
func ScanFile(path, root string) []Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	rel := path
	if r, err := filepath.Rel(root, path); err == nil {
		rel = filepath.ToSlash(r)
	}
	var out []Finding
	seen := map[string]bool{}
	for i, line := range lines {
		known := []string{}
		for _, r := range rules {
			for _, v := range r.find(line) {
				key := r.name + "\x00" + strconv.Itoa(i+1) + "\x00" + v
				if seen[key] {
					continue
				}
				if r.severity == "medium" {
					overlap := false
					for _, k := range known {
						if strings.Contains(k, v) || strings.Contains(v, k) {
							overlap = true
							break
						}
					}
					if overlap {
						continue
					}
				}
				seen[key] = true
				known = append(known, v)
				out = append(out, Finding{
					File: rel, Line: i + 1, Pattern: r.name,
					Severity: r.severity, Match: Mask(v),
				})
			}
		}
	}
	return out
}

// ScanPath возвращает находки и число просканированных файлов.
func ScanPath(target string, exclude []string, maxBytes int64) ([]Finding, int, error) {
	info, err := os.Stat(target)
	if err != nil {
		return nil, 0, err
	}
	ex := map[string]bool{}
	for _, e := range append(append([]string{}, DefaultExclude...), exclude...) {
		ex[e] = true
	}
	var files []string
	root := target
	if info.IsDir() {
		err = filepath.WalkDir(target, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if p != target && ex[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			files = append(files, p)
			return nil
		})
		if err != nil {
			return nil, 0, err
		}
	} else {
		files = []string{target}
		root = filepath.Dir(target)
	}
	var out []Finding
	scanned := 0
	for _, p := range files {
		if !isTextFile(p) {
			continue
		}
		st, err := os.Stat(p)
		if err != nil || st.Size() > maxBytes {
			continue
		}
		scanned++
		out = append(out, ScanFile(p, root)...)
	}
	return out, scanned, nil
}
