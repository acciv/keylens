package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMask(t *testing.T) {
	if got := Mask("short"); got != "*****" {
		t.Fatalf("Mask(short) = %q", got)
	}
	if got := Mask("ghp_abcdefghijklmnopqrstuvwxyz0123456789"); got != "ghp_...6789" {
		t.Fatalf("Mask(token) = %q", got)
	}
}

func TestRules(t *testing.T) {
	cases := []struct{ name, line, want string }{
		{"GitHub PAT (classic)", "token = ghp_abcdefghijklmnopqrstuvwxyz0123456789", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"},
		{"AWS Access Key ID", "AKIAABCDEFGHIJKLMNOP", "AKIAABCDEFGHIJKLMNOP"},
		{"Slack token", "xoxb-123456789012-abcdef", "xoxb-123456789012-abcdef"},
		{"OpenAI API key", "sk-abcdefghijklmnopqrstuvwx", "sk-abcdefghijklmnopqrstuvwx"},
		{"Private key", "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----"},
		{"Secret assignment", `api_key = "abcdefghijklmnop"`, "abcdefghijklmnop"},
	}
	for _, c := range cases {
		found := false
		for _, r := range rules {
			if r.name != c.name {
				continue
			}
			for _, v := range r.find(c.line) {
				if v == c.want {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("%s: не найдено %q в %q", c.name, c.want, c.line)
		}
	}
}

func TestScanPath(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("config.py", "key = \"ghp_abcdefghijklmnopqrstuvwxyz0123456789\"\n")
	write("notes.md", "api_key = \"abcdefghijklmnop\"\n")
	write(".git/config", "ghp_abcdefghijklmnopqrstuvwxyz0123456789\n")
	write("blob.bin", "ghp_abcdefghijklmnopqrstuvwxyz0123456789\n")

	findings, scanned, err := ScanPath(dir, nil, 2<<20)
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 2 {
		t.Fatalf("scanned = %d, want >= 2", scanned)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if strings.Contains(f.File, ".git/") || strings.HasSuffix(f.File, ".bin") {
			t.Errorf("недолжная находка: %s", f.File)
		}
		if f.Match == "" || strings.Contains(f.Match, "abcdefghijklmnopqrstuvwxyz") {
			t.Errorf("значение не замаскировано: %+v", f)
		}
	}
}
