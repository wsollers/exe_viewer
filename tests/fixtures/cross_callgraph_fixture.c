#include <stdint.h>

#if defined(_MSC_VER)
#define PEELF_NOINLINE __declspec(noinline)
#else
#define PEELF_NOINLINE __attribute__((noinline))
#endif

volatile int32_t peelf_cross_sink = 0;

PEELF_NOINLINE int32_t leaf(int32_t value) {
    peelf_cross_sink += value;
    return value + 7;
}

PEELF_NOINLINE int32_t first(int32_t value) {
    return leaf(value + 1);
}

PEELF_NOINLINE int32_t second(int32_t value) {
    return leaf(value + 2);
}

int main(void) {
    const int32_t a = first(10);
    const int32_t b = second(20);
    return (a + b + peelf_cross_sink) == 0 ? 1 : 0;
}
