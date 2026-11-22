#pragma once

#include <string>
#include <vector>

namespace keylens {

struct Finding {
    std::string file;
    int line = 0;
    std::string pattern;
    std::string severity;
    std::string match;
};

std::string mask(const std::string& value);
std::vector<Finding> scan_file(const std::string& path, const std::string& root);
std::vector<Finding> scan_path(const std::string& target,
                               const std::vector<std::string>& extra_exclude,
                               long long max_bytes,
                               int& scanned);
std::string to_json(const std::vector<Finding>& findings);

}  // namespace keylens
