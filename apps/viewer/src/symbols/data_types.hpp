#pragma once
#include "symbol_index.hpp"

namespace viewer {
struct DataEnumEnumerator {
    std::string name{};
    std::int64_t value = 0;

    auto operator<=>(const DataEnumEnumerator&) const = default;
};

struct DataMember {
    std::string name, type;
    std::uint64_t offset{}, size{};
    std::uint8_t bit_width = 0;
    std::uint8_t bit_offset = 0;

    auto operator<=>(const DataMember&) const = default;
};

struct DataTypeRecord {
    std::string name;
    std::uint64_t size{};
    bool is_union = false;
    std::vector<DataMember> members{};
    bool is_enum = false;
    bool is_enum_signed = true;
    bool is_custom_c = false;
    std::string underlying_type{};
    std::vector<DataEnumEnumerator> enum_constants{};
    std::vector<std::string> aliases{};

    auto operator<=>(const DataTypeRecord&) const = default;
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
    for (const auto& alias : type.aliases)
        if (symbol_name_matches(alias, query)) return true;
    for (const auto& member : type.members)
        if (symbol_name_matches(member.name, query) || symbol_name_matches(member.type, query)) return true;
    for (const auto& ec : type.enum_constants)
        if (symbol_name_matches(ec.name, query)) return true;
    return false;
}
}
