#include "keylens.hpp"

#include <cassert>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

namespace fs = std::filesystem;

static void write_file(const fs::path& path, const std::string& text) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path);
    out << text;
}

int main() {
    using keylens::mask;
    using keylens::scan_path;

    assert(mask("short") == "*****");
    assert(mask("ghp_abcdefghijklmnopqrstuvwxyz0123456789") == "ghp_...6789");

    const std::string token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
    fs::path dir = fs::temp_directory_path() / ("keylens-cpp-" + std::to_string(stamp));
    fs::create_directories(dir);
    write_file(dir / "config.py", "key = \"" + token + "\"\n");
    write_file(dir / "notes.md", "api_key = \"abcdefghijklmnop\"\n");
    write_file(dir / ".git" / "config", token + "\n");
    write_file(dir / "blob.bin", token + "\n");

    int scanned = 0;
    auto findings = scan_path(dir.string(), {}, 2 << 20, scanned);
    assert(scanned >= 2);
    assert(findings.size() == 2);
    for (const auto& f : findings) {
        assert(f.file.find(".git/") == std::string::npos);
        assert(f.match.find("abcdefghijklmnopqrstuvwxyz") == std::string::npos);
    }
    assert(scan_path(dir.string() + "/missing", {}, 2, scanned).empty());

    fs::remove_all(dir);
    std::cout << "all tests passed\n";
    return 0;
}
