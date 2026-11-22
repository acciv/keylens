#include "keylens.hpp"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

void usage() {
    std::cerr << "keylens — поиск утекших API-ключей и токенов\n\n"
                 "Использование:\n"
                 "  keylens scan [путь] [--json] [--exclude DIR] [--max-size MB] [--quiet]\n\n"
                 "Флаги:\n"
                 "  --json              вывод в формате JSON\n"
                 "  --exclude DIR       исключить каталог (можно повторять)\n"
                 "  --max-size MB       максимальный размер файла (по умолчанию 2)\n"
                 "  --quiet             только код возврата\n"
                 "  --version           версия\n";
}

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);
    if (args.empty()) {
        usage();
        return 2;
    }
    if (args[0] == "--version" || args[0] == "-v") {
        std::cout << "keylens 0.1.0\n";
        return 0;
    }
    if (args[0] != "scan") {
        usage();
        return 2;
    }

    std::string path = ".";
    bool json_out = false, quiet = false;
    std::vector<std::string> excludes;
    long long max_mb = 2;

    for (size_t i = 1; i < args.size(); ++i) {
        const std::string& arg = args[i];
        if (arg == "--json") {
            json_out = true;
        } else if (arg == "--quiet") {
            quiet = true;
        } else if (arg == "-h" || arg == "--help") {
            usage();
            return 0;
        } else if (arg == "--exclude" || arg == "--max-size") {
            if (i + 1 >= args.size()) {
                usage();
                return 2;
            }
            ++i;
            if (arg == "--exclude") {
                excludes.push_back(args[i]);
            } else {
                char* end = nullptr;
                long long n = std::strtoll(args[i].c_str(), &end, 10);
                if (end == args[i].c_str() || *end != '\0' || n < 0) {
                    std::cerr << "keylens: неверный --max-size\n";
                    return 2;
                }
                max_mb = n;
            }
        } else if ((!arg.empty() && arg[0] == '-') || path != ".") {
            usage();
            return 2;
        } else {
            path = arg;
        }
    }

    std::error_code ec;
    if (!fs::exists(fs::path(path), ec)) {
        std::cerr << "keylens: путь не найден: " << path << "\n";
        return 2;
    }

    int scanned = 0;
    auto findings = keylens::scan_path(path, excludes, max_mb * 1024 * 1024, scanned);

    if (json_out) {
        std::cout << keylens::to_json(findings) << "\n";
    } else if (!quiet) {
        std::cout << "🔍 keylens: просмотрено файлов: " << scanned << "\n";
        if (!findings.empty()) {
            std::cout << "⚠️  Найдено потенциальных секретов: " << findings.size() << "\n\n";
            for (const auto& f : findings) {
                std::cout << "  [" << f.severity << "] " << f.match << " " << f.file << ":"
                          << f.line << " — " << f.pattern << "\n";
            }
        } else {
            std::cout << "✅ Секретов не найдено\n";
        }
    }
    return findings.empty() ? 0 : 1;
}
