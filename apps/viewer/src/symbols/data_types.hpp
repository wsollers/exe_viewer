#pragma once
#include "symbol_index.hpp"

namespace viewer {
struct DataMember {
    std::string name, type;
    std::uint64_t offset{}, size{};
};
struct DataTypeRecord {
    std::string name;
    std::uint64_t size{};
    bool is_union = false;
    std::vector<DataMember> members;
};

struct AppliedStructureBinding {
    std::uint64_t address = 0;
    bool is_file_offset = false;
    std::string type_name{};
    std::uint32_t count = 1;
    std::string label{};

    auto operator<=>(const AppliedStructureBinding&) const = default;
};

struct Bookmark {
    std::uint64_t address = 0;
    bool is_file_offset = false;
    std::string label{};
    std::string category{};
    std::string note{};

    auto operator<=>(const Bookmark&) const = default;
};
[[nodiscard]] inline bool type_matches(const DataTypeRecord& type, std::string_view query) {
    if (symbol_name_matches(type.name, query)) return true;
    for (const auto& member : type.members)
        if (symbol_name_matches(member.name, query) || symbol_name_matches(member.type, query)) return true;
    return false;
}
}
