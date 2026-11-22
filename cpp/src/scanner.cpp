#include "keylens.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>

namespace fs = std::filesystem;
namespace keylens {
namespace {

using Finder = std::vector<std::string> (*)(const std::string&);

bool is_alnum(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}
bool is_upper_digit(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}
bool is_word(unsigned char c) { return is_alnum(c) || c == '_'; }
bool is_secret_char(unsigned char c) { return is_alnum(c) || c == '-' || c == '_'; }

std::vector<std::string> find_fixed(const std::string& line, const std::string& prefix,
                                    size_t n, bool (*valid)(unsigned char)) {
    std::vector<std::string> out;
    size_t start = 0;
    while (start < line.size()) {
        size_t pos = line.find(prefix, start);
        if (pos == std::string::npos) break;
        size_t end = pos + prefix.size();
        if (end + n <= line.size()) {
            bool ok = true;
            for (size_t i = 0; i < n; ++i) {
                if (!valid(static_cast<unsigned char>(line[end + i]))) {
                    ok = false;
                    break;
                }
            }
            if (ok) {
                out.push_back(line.substr(pos, prefix.size() + n));
                start = end + n;
                continue;
            }
        }
        start = pos + 1;
    }
    return out;
}

std::vector<std::string> find_variable(const std::string& line, const std::string& prefix,
                                       size_t min, bool (*valid)(unsigned char)) {
    std::vector<std::string> out;
    size_t start = 0;
    while (start < line.size()) {
        size_t pos = line.find(prefix, start);
        if (pos == std::string::npos) break;
        size_t end = pos + prefix.size();
        while (end < line.size() && valid(static_cast<unsigned char>(line[end]))) ++end;
        if (end - pos - prefix.size() >= min) {
            out.push_back(line.substr(pos, end - pos));
            start = end;
        } else {
            start = pos + 1;
        }
    }
    return out;
}

std::vector<std::string> find_slack(const std::string& line) {
    std::vector<std::string> out;
    const std::string kinds = "baprs";
    for (size_t i = 0; i + 5 <= line.size();) {
        if (line.substr(i, 3) == "xox" && kinds.find(line[i + 3]) != std::string::npos &&
            line[i + 4] == '-') {
            size_t j = i + 5;
            while (j < line.size() && is_secret_char(static_cast<unsigned char>(line[j]))) ++j;
            if (j - (i + 5) >= 10) {
                out.push_back(line.substr(i, j - i));
                i = j;
                continue;
            }
        }
        ++i;
    }
    return out;
}

std::vector<std::string> find_telegram(const std::string& line) {
    std::vector<std::string> out;
    size_t i = 0;
    while (i < line.size()) {
        unsigned char c = static_cast<unsigned char>(line[i]);
        if (c < '0' || c > '9' || (i > 0 && is_word(static_cast<unsigned char>(line[i - 1])))) {
            ++i;
            continue;
        }
        size_t j = i;
        while (j < line.size() && line[j] >= '0' && line[j] <= '9' && j - i < 10) ++j;
        if (j - i < 8 || j >= line.size() || line[j] != ':') {
            i = std::max(j, i + 1);
            continue;
        }
        size_t k = j + 1;
        while (k < line.size() && is_secret_char(static_cast<unsigned char>(line[k]))) ++k;
        if (k - (j + 1) == 35 &&
            (k == line.size() || !is_word(static_cast<unsigned char>(line[k])))) {
            out.push_back(line.substr(i, k - i));
            i = k;
        } else {
            ++i;
        }
    }
    return out;
}

std::vector<std::string> find_pem(const std::string& line) {
    static const char* prefixes[] = {
        "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
    };
    std::vector<std::string> out;
    for (const char* p : prefixes) {
        size_t pos = 0;
        std::string prefix(p);
        while ((pos = line.find(prefix, pos)) != std::string::npos) {
            out.push_back(prefix);
            pos += prefix.size();
        }
    }
    return out;
}

std::vector<std::string> find_assignment(const std::string& line) {
    std::string lower = line;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    std::vector<std::string> out;
    static const char* keys[] = {"api_key", "apikey", "api-key", "secret", "token"};
    for (const char* key : keys) {
        std::string k(key);
        size_t start = 0;
        while (start + k.size() <= line.size()) {
            size_t pos = lower.find(k, start);
            if (pos == std::string::npos) break;
            size_t j = pos + k.size();
            while (j < line.size() && (line[j] == ' ' || line[j] == '\t')) ++j;
            if (j < line.size() && (line[j] == ':' || line[j] == '=')) {
                ++j;
                while (j < line.size() && (line[j] == ' ' || line[j] == '\t')) ++j;
                if (j < line.size() && (line[j] == '\'' || line[j] == '"')) {
                    char quote = line[j++];
                    size_t begin = j;
                    while (j < line.size() && is_secret_char(static_cast<unsigned char>(line[j]))) ++j;
                    if (j - begin >= 16 && j < line.size() && line[j] == quote) {
                        out.push_back(line.substr(begin, j - begin));
                        start = j;
                        continue;
                    }
                }
            }
            start = pos + 1;
        }
    }
    return out;
}

std::vector<std::string> github_classic(const std::string& l) {
    return find_fixed(l, "ghp_", 36, is_alnum);
}
std::vector<std::string> github_fine(const std::string& l) {
    return find_variable(l, "github_pat_", 60, is_secret_char);
}
std::vector<std::string> github_oauth(const std::string& l) {
    return find_fixed(l, "gho_", 36, is_alnum);
}
std::vector<std::string> aws_key(const std::string& l) {
    return find_fixed(l, "AKIA", 16, is_upper_digit);
}
std::vector<std::string> openai_key(const std::string& l) {
    return find_variable(l, "sk-", 20, is_alnum);
}

struct Rule {
    const char* name;
    const char* severity;
    Finder find;
};

const Rule RULES[] = {
    {"GitHub PAT (classic)", "high", github_classic},
    {"GitHub PAT (fine-grained)", "high", github_fine},
    {"GitHub OAuth token", "high", github_oauth},
    {"AWS Access Key ID", "high", aws_key},
    {"Slack token", "high", find_slack},
    {"OpenAI API key", "high", openai_key},
    {"Telegram bot token", "high", find_telegram},
    {"Private key", "high", find_pem},
    {"Secret assignment", "medium", find_assignment},
};

const std::set<std::string> TEXT_EXT = {
    "bash", "c", "cfg", "cpp", "css", "cs", "env", "go", "gradle", "h",
    "hpp", "html", "ini", "java", "js", "json", "kt", "md", "php",
    "properties", "py", "rb", "rs", "sh", "sql", "tf", "toml", "ts",
    "txt", "xml", "yaml", "yml",
};

bool is_text_file(const fs::path& p) {
    std::string name = p.filename().string();
    if (name == "Dockerfile" || name == "Makefile" || name == ".env" || name == ".gitignore") {
        return true;
    }
    std::string ext = p.extension().string();
    if (!ext.empty() && ext[0] == '.') ext.erase(ext.begin());
    std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return TEXT_EXT.count(ext) > 0;
}

void walk(const fs::path& dir, const std::set<std::string>& excluded,
          std::vector<fs::path>& files) {
    std::error_code ec;
    fs::directory_iterator it(dir, ec), end;
    for (; it != end && !ec; it.increment(ec)) {
        fs::path p = it->path();
        if (fs::is_directory(p, ec)) {
            if (excluded.count(p.filename().string())) continue;
            walk(p, excluded, files);
        } else {
            files.push_back(p);
        }
    }
}

std::string escape(const std::string& s) {
    std::string out;
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 32) {
                    static const char* hex = "0123456789abcdef";
                    out += "\\u00";
                    out += hex[c >> 4];
                    out += hex[c & 15];
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

}  // namespace

std::string mask(const std::string& value) {
    if (value.size() <= 8) return std::string(value.size(), '*');
    return value.substr(0, 4) + "..." + value.substr(value.size() - 4);
}

std::vector<Finding> scan_file(const std::string& path, const std::string& root) {
    std::ifstream in(path);
    if (!in) return {};
    std::string rel = path;
    try {
        rel = fs::relative(fs::path(path), fs::path(root)).generic_string();
    } catch (...) {
    }
    std::vector<Finding> out;
    std::set<std::string> seen;
    std::string line;
    int line_no = 0;
    while (std::getline(in, line)) {
        ++line_no;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::vector<std::string> known;
        for (const Rule& rule : RULES) {
            for (const std::string& value : rule.find(line)) {
                std::string key = std::string(rule.name) + "\0" + std::to_string(line_no) + "\0" + value;
                if (seen.count(key)) continue;
                if (std::string(rule.severity) == "medium") {
                    bool overlap = false;
                    for (const std::string& k : known) {
                        if (k.find(value) != std::string::npos || value.find(k) != std::string::npos) {
                            overlap = true;
                            break;
                        }
                    }
                    if (overlap) continue;
                }
                seen.insert(key);
                known.push_back(value);
                out.push_back({rel, line_no, rule.name, rule.severity, mask(value)});
            }
        }
    }
    return out;
}

std::vector<Finding> scan_path(const std::string& target,
                               const std::vector<std::string>& extra_exclude,
                               long long max_bytes, int& scanned) {
    scanned = 0;
    std::error_code ec;
    fs::path p(target);
    if (!fs::exists(p, ec)) return {};
    std::set<std::string> excluded = {
        ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__",
        "dist", "build", ".mypy_cache", ".pytest_cache", ".idea", ".vscode",
    };
    for (const std::string& e : extra_exclude) excluded.insert(e);

    std::vector<fs::path> files;
    fs::path root = fs::is_directory(p, ec) ? p : p.parent_path();
    if (fs::is_directory(p, ec)) {
        walk(p, excluded, files);
    } else {
        files.push_back(p);
    }

    std::vector<Finding> out;
    for (const fs::path& f : files) {
        if (!is_text_file(f)) continue;
        uintmax_t size = fs::file_size(f, ec);
        if (ec || static_cast<long long>(size) > max_bytes) continue;
        ++scanned;
        auto found = scan_file(f.string(), root.string());
        out.insert(out.end(), found.begin(), found.end());
    }
    return out;
}

std::string to_json(const std::vector<Finding>& findings) {
    std::ostringstream out;
    out << "[\n";
    for (size_t i = 0; i < findings.size(); ++i) {
        const Finding& f = findings[i];
        out << "  {\n"
            << "    \"file\": \"" << escape(f.file) << "\",\n"
            << "    \"line\": " << f.line << ",\n"
            << "    \"pattern\": \"" << escape(f.pattern) << "\",\n"
            << "    \"severity\": \"" << escape(f.severity) << "\",\n"
            << "    \"match\": \"" << escape(f.match) << "\"\n"
            << "  }";
        if (i + 1 < findings.size()) out << ',';
        out << '\n';
    }
    out << ']';
    return out.str();
}

}  // namespace keylens
