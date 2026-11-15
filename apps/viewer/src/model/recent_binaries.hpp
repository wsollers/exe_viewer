#pragma once
#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <string>
#include <vector>

namespace viewer {
// UI-independent, most-recent-first history; persisted paths use UTF-8.
class RecentBinaries {
public:
    static constexpr std::size_t capacity = 5;
    [[nodiscard]] const auto& paths() const noexcept { return paths_; }
    void remember(const std::filesystem::path& path) {
        if (path.empty()) return;
        std::error_code ec;
        auto normalized = std::filesystem::absolute(path, ec).lexically_normal();
        if (ec) return;
        std::erase_if(paths_, [&](const auto& existing) {
#ifdef _WIN32
            auto left = existing.wstring(), right = normalized.wstring();
            std::ranges::transform(left, left.begin(), [](wchar_t c) { return std::towlower(c); });
            std::ranges::transform(right, right.begin(), [](wchar_t c) { return std::towlower(c); });
            return left == right;
#else
            return existing == normalized;
#endif
        });
        paths_.insert(paths_.begin(), std::move(normalized));
        if (paths_.size() > capacity) paths_.resize(capacity);
    }
    void load(const std::filesystem::path& storage, const std::filesystem::path& seed) {
        paths_.clear();
        std::ifstream input(storage, std::ios::binary);
        std::string magic; unsigned version = 0;
        std::vector<std::filesystem::path> loaded;
        if (input >> magic >> version; magic == "PEELF_RECENT" && version == 1) {
            std::string encoded;
            while (loaded.size() < capacity && input >> std::quoted(encoded)) {
                if (!encoded.empty()) loaded.emplace_back(std::u8string(encoded.begin(), encoded.end()));
            }
        }
        for (auto it = loaded.rbegin(); it != loaded.rend(); ++it) remember(*it);
        if (paths_.empty()) remember(seed);
    }
    [[nodiscard]] bool save(const std::filesystem::path& storage) const {
        std::ofstream output(storage, std::ios::binary | std::ios::trunc);
        output << "PEELF_RECENT 1\n";
        for (const auto& path : paths_) {
            const auto utf8 = path.generic_u8string();
            output << std::quoted(std::string(utf8.begin(), utf8.end())) << '\n';
        }
        output.close();
        return !output.fail();
    }
private:
    std::vector<std::filesystem::path> paths_;
};
}
