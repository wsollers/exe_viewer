#include <cstdint>

#if defined(_MSC_VER)
#define PEELF_NOINLINE __declspec(noinline)
#else
#define PEELF_NOINLINE __attribute__((noinline))
#endif

namespace {

volatile std::int32_t g_sink = 0;

} // namespace

extern "C" PEELF_NOINLINE std::int32_t peelf_fixture_leaf(std::int32_t value) {
    g_sink += value;
    return value + 7;
}

extern "C" PEELF_NOINLINE std::int32_t peelf_fixture_first(std::int32_t value) {
    return peelf_fixture_leaf(value + 1);
}

extern "C" PEELF_NOINLINE std::int32_t peelf_fixture_second(std::int32_t value) {
    return peelf_fixture_leaf(value + 2);
}

int main() {
    const std::int32_t first = peelf_fixture_first(10);
    const std::int32_t second = peelf_fixture_second(20);
    return (first + second + g_sink) == 0 ? 1 : 0;
}
