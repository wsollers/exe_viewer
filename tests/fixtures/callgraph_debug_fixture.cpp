#include <cstdint>

#if defined(_MSC_VER)
#define PEELF_NOINLINE __declspec(noinline)
#else
#define PEELF_NOINLINE __attribute__((noinline))
#endif

namespace {

volatile std::int32_t g_sink = 0;

} // namespace

namespace peelf_fixture {

PEELF_NOINLINE std::int32_t leaf(std::int32_t value) {
    g_sink += value;
    return value + 7;
}

PEELF_NOINLINE std::int32_t first(std::int32_t value) {
    return leaf(value + 1);
}

PEELF_NOINLINE std::int32_t second(std::int32_t value) {
    return leaf(value + 2);
}

} // namespace peelf_fixture

int main() {
    const std::int32_t first = peelf_fixture::first(10);
    const std::int32_t second = peelf_fixture::second(20);
    return (first + second + g_sink) == 0 ? 1 : 0;
}
