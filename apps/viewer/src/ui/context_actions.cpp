#include "ui/context_actions.hpp"

#include <algorithm>
#include <format>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace viewer {
namespace {

[[nodiscard]] constexpr bool is_utf8_continuation(unsigned char b) noexcept {
    return b >= 0x80u && b <= 0xBFu;
}

void append_json_escaped(std::string& out, std::string_view text) {
    out.push_back('"');
    for (std::size_t i = 0u; i < text.size();) {
        const auto b0 = static_cast<unsigned char>(text[i]);
        if (b0 < 0x80u) {
            switch (b0) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (b0 < 0x20u) {
                        out += std::format("\\u{:04x}", static_cast<unsigned int>(b0));
                    } else {
                        out.push_back(static_cast<char>(b0));
                    }
                    break;
            }
            ++i;
            continue;
        }

        if (b0 >= 0xC2u && b0 <= 0xDFu) {
            if (i + 1u < text.size() && is_utf8_continuation(static_cast<unsigned char>(text[i + 1u]))) {
                out.append(text.substr(i, 2u));
                i += 2u;
            } else {
                out += "\\uFFFD";
                ++i;
            }
            continue;
        }

        if (b0 >= 0xE0u && b0 <= 0xEFu) {
            const auto valid_second = [b0](unsigned char b1) noexcept -> bool {
                if (b0 == 0xE0u) {
                    return b1 >= 0xA0u && b1 <= 0xBFu;
                }
                if (b0 == 0xEDu) {
                    return b1 >= 0x80u && b1 <= 0x9Fu;
                }
                return is_utf8_continuation(b1);
            };
            if (i + 1u >= text.size() || !valid_second(static_cast<unsigned char>(text[i + 1u]))) {
                out += "\\uFFFD";
                ++i;
            } else if (i + 2u >= text.size() || !is_utf8_continuation(static_cast<unsigned char>(text[i + 2u]))) {
                out += "\\uFFFD";
                i += 2u;
            } else {
                out.append(text.substr(i, 3u));
                i += 3u;
            }
            continue;
        }

        if (b0 >= 0xF0u && b0 <= 0xF4u) {
            const auto valid_second = [b0](unsigned char b1) noexcept -> bool {
                if (b0 == 0xF0u) {
                    return b1 >= 0x90u && b1 <= 0xBFu;
                }
                if (b0 == 0xF4u) {
                    return b1 >= 0x80u && b1 <= 0x8Fu;
                }
                return is_utf8_continuation(b1);
            };
            if (i + 1u >= text.size() || !valid_second(static_cast<unsigned char>(text[i + 1u]))) {
                out += "\\uFFFD";
                ++i;
            } else if (i + 2u >= text.size() || !is_utf8_continuation(static_cast<unsigned char>(text[i + 2u]))) {
                out += "\\uFFFD";
                i += 2u;
            } else if (i + 3u >= text.size() || !is_utf8_continuation(static_cast<unsigned char>(text[i + 3u]))) {
                out += "\\uFFFD";
                i += 3u;
            } else {
                out.append(text.substr(i, 4u));
                i += 4u;
            }
            continue;
        }

        out += "\\uFFFD";
        ++i;
    }
    out.push_back('"');
}

[[nodiscard]] constexpr bool has_valid_decompile_target(
    const InspectableEntity& entity,
    bool has_static_image) noexcept {
    if (!entity.va.has_value()) {
        return false;
    }
    return *entity.va != 0u || (has_static_image && entity.file_offset.has_value());
}

[[nodiscard]] constexpr std::size_t clamp_highlight_size(std::uint64_t raw_size) noexcept {
    constexpr std::uint64_t kMaxHighlight = 65536u;
    if (raw_size == 0u) {
        return 1u;
    }
    const std::uint64_t bounded = std::min<std::uint64_t>(
        raw_size,
        std::min<std::uint64_t>(kMaxHighlight,
                                static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())));
    return static_cast<std::size_t>(bounded);
}

[[nodiscard]] bool target_supports_byte_navigation(
    const peelf::TargetCapabilityMatrix& capabilities,
    bool has_static_image) noexcept {
    if (has_static_image) {
        return true;
    }
    const peelf::BackendKind backend = capabilities.profile().backend;
    if (backend == peelf::BackendKind::LiveNativeReadOnly ||
        backend == peelf::BackendKind::ActiveDebugger ||
        peelf::is_crash_dump_backend(backend) ||
        backend == peelf::BackendKind::RemoteGdbRsp) {
        return true;
    }
    return capabilities.get(peelf::Operation::ImageParsing).can_execute();
}

} // namespace

std::vector<EvaluatedContextAction> evaluate_context_actions(
    const InspectableEntity& entity,
    const peelf::TargetCapabilityMatrix& capabilities,
    bool has_static_image,
    bool has_active_debugger) {
    std::vector<EvaluatedContextAction> actions;
    actions.reserve(kContextActionCount);

    // 1. CopyVirtualAddress
    actions.push_back(EvaluatedContextAction{
        .kind = ContextActionKind::CopyVirtualAddress,
        .label = entity.va.has_value()
                     ? std::format("Copy Virtual Address (0x{:X})", *entity.va)
                     : std::string("Copy Virtual Address"),
        .enabled = entity.va.has_value(),
        .disabled_reason = entity.va.has_value()
                               ? std::string{}
                               : std::string("Entity has no virtual address"),
    });

    // 2. CopyFileOffset
    actions.push_back(EvaluatedContextAction{
        .kind = ContextActionKind::CopyFileOffset,
        .label = entity.file_offset.has_value()
                     ? std::format("Copy File Offset (0x{:X})", *entity.file_offset)
                     : std::string("Copy File Offset"),
        .enabled = entity.file_offset.has_value(),
        .disabled_reason = entity.file_offset.has_value()
                               ? std::string{}
                               : (has_static_image
                                      ? std::string("Entity has no mapped file offset")
                                      : std::string("Live/runtime entity has no on-disk file offset")),
    });

    // 3. CopyLabel
    const bool has_label = !entity.symbol_or_label.empty();
    actions.push_back(EvaluatedContextAction{
        .kind = ContextActionKind::CopyLabel,
        .label = "Copy Symbol / Label",
        .enabled = has_label,
        .disabled_reason = has_label ? std::string{} : std::string("Entity has no symbol or label"),
    });

    // 4. CopyJsonSummary
    actions.push_back(EvaluatedContextAction{
        .kind = ContextActionKind::CopyJsonSummary,
        .label = "Copy Entity Summary as JSON",
        .enabled = true,
        .disabled_reason = {},
    });

    const bool byte_nav_ready = target_supports_byte_navigation(capabilities, has_static_image);
    const bool has_navigable_coord =
        entity.va.has_value() || (has_static_image && entity.file_offset.has_value());
    const std::string img_unready_reason =
        !capabilities.get(peelf::Operation::ImageParsing).reason.empty()
            ? capabilities.get(peelf::Operation::ImageParsing).reason
            : std::string("No active binary image or process session loaded");

    // 5. FollowInHex
    {
        bool enabled = false;
        std::string reason;
        if (!byte_nav_ready) {
            reason = img_unready_reason;
        } else if (!has_navigable_coord) {
            reason = entity.file_offset.has_value()
                         ? "File offset navigation requires a static binary image"
                         : "Entity has no virtual address or file offset";
        } else {
            enabled = true;
        }
        actions.push_back(EvaluatedContextAction{
            .kind = ContextActionKind::FollowInHex,
            .label = "Follow in Hex View",
            .enabled = enabled,
            .disabled_reason = std::move(reason),
        });
    }

    // 6. FollowInDisassembly
    {
        const peelf::Capability& disasm_cap = capabilities.get(peelf::Operation::Disassembly);
        bool enabled = false;
        std::string reason;
        if (!disasm_cap.can_execute()) {
            reason = !disasm_cap.reason.empty()
                         ? disasm_cap.reason
                         : "Disassembly is not supported for this target";
        } else if (!has_navigable_coord) {
            reason = entity.file_offset.has_value()
                         ? "File offset disassembly requires a static binary image"
                         : "Entity has no addressable location to disassemble";
        } else {
            enabled = true;
        }
        actions.push_back(EvaluatedContextAction{
            .kind = ContextActionKind::FollowInDisassembly,
            .label = "Follow in Disassembly",
            .enabled = enabled,
            .disabled_reason = std::move(reason),
        });
    }

    // 7. FollowInDecompiler
    {
        const peelf::Capability& struct_dec = capabilities.get(peelf::Operation::StructuredDecompile);
        const bool any_decompiler =
            struct_dec.can_execute() ||
            capabilities.get(peelf::Operation::ExternalGhidraDecompile).can_execute() ||
            capabilities.get(peelf::Operation::ExternalRetDecDecompile).can_execute() ||
            capabilities.get(peelf::Operation::ExternalBinaryNinjaDecompile).can_execute();
        bool enabled = false;
        std::string reason;
        if (!byte_nav_ready) {
            reason = img_unready_reason;
        } else if (!any_decompiler) {
            reason = !struct_dec.reason.empty()
                         ? struct_dec.reason
                         : "Decompilation is not supported for this target";
        } else if (!has_valid_decompile_target(entity, has_static_image)) {
            reason = "Decompilation requires a valid navigable virtual address";
        } else {
            enabled = true;
        }
        actions.push_back(EvaluatedContextAction{
            .kind = ContextActionKind::FollowInDecompiler,
            .label = "Follow in Decompiler",
            .enabled = enabled,
            .disabled_reason = std::move(reason),
        });
    }

    // 8. FollowInStructureView
    {
        bool enabled = false;
        std::string reason;
        if (!byte_nav_ready) {
            reason = img_unready_reason;
        } else if (!has_navigable_coord) {
            reason = entity.file_offset.has_value()
                         ? "File offset structure view requires a static binary image"
                         : "Entity has no virtual address or file offset";
        } else {
            enabled = true;
        }
        actions.push_back(EvaluatedContextAction{
            .kind = ContextActionKind::FollowInStructureView,
            .label = "Follow in Structure View",
            .enabled = enabled,
            .disabled_reason = std::move(reason),
        });
    }

    // 9. AddBookmark
    {
        bool enabled = false;
        std::string reason;
        if (!byte_nav_ready) {
            reason = img_unready_reason;
        } else if (!has_navigable_coord) {
            reason = "Bookmark requires a virtual address or file offset";
        } else {
            enabled = true;
        }
        actions.push_back(EvaluatedContextAction{
            .kind = ContextActionKind::AddBookmark,
            .label = "Add / Toggle Bookmark",
            .enabled = enabled,
            .disabled_reason = std::move(reason),
        });
    }

    // 10. ToggleSoftwareBreakpoint
    {
        const peelf::Capability& bp_cap = capabilities.get(peelf::Operation::SoftwareBreakpoints);
        bool enabled = false;
        std::string reason;
        if (!bp_cap.can_execute()) {
            reason = !bp_cap.reason.empty()
                         ? bp_cap.reason
                         : "Software breakpoints are not supported for this target";
        } else if (!has_active_debugger) {
            reason = "No active debugger session attached";
        } else if (!entity.va.has_value()) {
            reason = "Software breakpoint requires a virtual address";
        } else {
            enabled = true;
        }
        actions.push_back(EvaluatedContextAction{
            .kind = ContextActionKind::ToggleSoftwareBreakpoint,
            .label = "Toggle Software Breakpoint",
            .enabled = enabled,
            .disabled_reason = std::move(reason),
        });
    }

    return actions;
}

std::string format_entity_json_summary(const InspectableEntity& entity) {
    std::string out;
    out.reserve(256u + entity.extra_json_fields.size() * 48u);
    out += "{\n";

    out += "  \"va\": ";
    if (entity.va.has_value()) {
        append_json_escaped(out, std::format("0x{:X}", *entity.va));
    } else {
        out += "null";
    }
    out += ",\n";

    out += "  \"file_offset\": ";
    if (entity.file_offset.has_value()) {
        append_json_escaped(out, std::format("0x{:X}", *entity.file_offset));
    } else {
        out += "null";
    }
    out += ",\n";

    out += std::format("  \"size\": {},\n", entity.size);

    out += "  \"symbol_or_label\": ";
    append_json_escaped(out, entity.symbol_or_label);
    out += ",\n";

    out += "  \"module_name\": ";
    append_json_escaped(out, entity.module_name);

    if (!entity.extra_json_fields.empty()) {
        // Deduplicate keys preserving last value per first-seen key order so output is valid RFC 8259 JSON.
        std::vector<std::pair<std::string_view, std::string_view>> unique_fields;
        unique_fields.reserve(entity.extra_json_fields.size());
        for (const auto& [k, v] : entity.extra_json_fields) {
            if (k.empty()) {
                continue;
            }
            const auto existing = std::ranges::find_if(
                unique_fields,
                [&k](const auto& kv) { return kv.first == k; });
            if (existing != unique_fields.end()) {
                existing->second = v;
            } else {
                unique_fields.emplace_back(k, v);
            }
        }

        if (!unique_fields.empty()) {
            out += ",\n  \"extra\": {\n";
            for (std::size_t i = 0u; i < unique_fields.size(); ++i) {
                out += "    ";
                append_json_escaped(out, unique_fields[i].first);
                out += ": ";
                append_json_escaped(out, unique_fields[i].second);
                if (i + 1u < unique_fields.size()) {
                    out += ',';
                }
                out += '\n';
            }
            out += "  }";
        }
    }

    out += "\n}";
    return out;
}

std::optional<std::string> format_context_copy_payload(
    ContextActionKind kind,
    const InspectableEntity& entity) {
    switch (kind) {
        case ContextActionKind::CopyVirtualAddress:
            if (!entity.va.has_value()) {
                return std::nullopt;
            }
            return std::format("0x{:X}", *entity.va);
        case ContextActionKind::CopyFileOffset:
            if (!entity.file_offset.has_value()) {
                return std::nullopt;
            }
            return std::format("0x{:X}", *entity.file_offset);
        case ContextActionKind::CopyLabel:
            if (entity.symbol_or_label.empty()) {
                return std::nullopt;
            }
            return entity.symbol_or_label;
        case ContextActionKind::CopyJsonSummary:
            return format_entity_json_summary(entity);
        case ContextActionKind::FollowInHex:
        case ContextActionKind::FollowInDisassembly:
        case ContextActionKind::FollowInDecompiler:
        case ContextActionKind::FollowInStructureView:
        case ContextActionKind::AddBookmark:
        case ContextActionKind::ToggleSoftwareBreakpoint:
            return std::nullopt;
    }
    return std::nullopt;
}

std::optional<NavigationRequest> build_context_navigation_request(
    ContextActionKind kind,
    const InspectableEntity& entity,
    bool has_static_image) noexcept {
    const std::size_t highlight_sz = clamp_highlight_size(entity.size);

    switch (kind) {
        case ContextActionKind::FollowInHex:
            if (entity.va.has_value()) {
                return NavigationRequest{
                    .kind = NavigationRequest::Kind::Address,
                    .target = *entity.va,
                    .preferred_view = PreferredView::Hex,
                    .highlight_size = highlight_sz,
                };
            }
            if (has_static_image && entity.file_offset.has_value()) {
                return NavigationRequest{
                    .kind = NavigationRequest::Kind::Offset,
                    .target = *entity.file_offset,
                    .preferred_view = PreferredView::Hex,
                    .highlight_size = highlight_sz,
                };
            }
            return std::nullopt;

        case ContextActionKind::FollowInDisassembly:
            if (entity.va.has_value()) {
                return NavigationRequest{
                    .kind = NavigationRequest::Kind::Address,
                    .target = *entity.va,
                    .preferred_view = PreferredView::Disassembly,
                    .highlight_size = highlight_sz,
                };
            }
            if (has_static_image && entity.file_offset.has_value()) {
                return NavigationRequest{
                    .kind = NavigationRequest::Kind::Offset,
                    .target = *entity.file_offset,
                    .preferred_view = PreferredView::Disassembly,
                    .highlight_size = highlight_sz,
                };
            }
            return std::nullopt;

        case ContextActionKind::FollowInDecompiler:
            if (has_valid_decompile_target(entity, has_static_image)) {
                return NavigationRequest{
                    .kind = NavigationRequest::Kind::Address,
                    .target = *entity.va,
                    .preferred_view = PreferredView::Disassembly,
                    .highlight_size = highlight_sz,
                    .request_decompile = true,
                };
            }
            return std::nullopt;

        case ContextActionKind::FollowInStructureView:
            if (entity.va.has_value()) {
                return NavigationRequest{
                    .kind = NavigationRequest::Kind::Address,
                    .target = *entity.va,
                    .preferred_view = PreferredView::Details,
                    .highlight_size = highlight_sz,
                    .open_structure_view = true,
                };
            }
            if (has_static_image && entity.file_offset.has_value()) {
                return NavigationRequest{
                    .kind = NavigationRequest::Kind::Offset,
                    .target = *entity.file_offset,
                    .preferred_view = PreferredView::Details,
                    .highlight_size = highlight_sz,
                    .open_structure_view = true,
                };
            }
            return std::nullopt;

        case ContextActionKind::CopyVirtualAddress:
        case ContextActionKind::CopyFileOffset:
        case ContextActionKind::CopyLabel:
        case ContextActionKind::CopyJsonSummary:
        case ContextActionKind::AddBookmark:
        case ContextActionKind::ToggleSoftwareBreakpoint:
            return std::nullopt;
    }
    return std::nullopt;
}

bool enqueue_context_navigation_action(
    NavigationRequestQueue& queue,
    ContextActionKind kind,
    const InspectableEntity& entity,
    bool has_static_image) {
    if (auto req = build_context_navigation_request(kind, entity, has_static_image)) {
        queue.enqueue(std::move(*req));
        return true;
    }
    return false;
}

} // namespace viewer
