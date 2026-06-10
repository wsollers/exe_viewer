#include <stdint.h>

#if defined(PEELF_SHARED_FIXTURE)
#include <stdio.h>
#endif

#if defined(_MSC_VER)
#define PEELF_NOINLINE __declspec(noinline)
#else
#define PEELF_NOINLINE __attribute__((noinline))
#endif

#if defined(_WIN32) && defined(PEELF_SHARED_FIXTURE)
#define PEELF_EXPORT __declspec(dllexport)
#else
#define PEELF_EXPORT
#endif

volatile int32_t peelf_cross_sink = 0;

PEELF_EXPORT PEELF_NOINLINE int32_t leaf(int32_t value) {
    peelf_cross_sink += value;
    return value + 7;
}

PEELF_EXPORT PEELF_NOINLINE int32_t first(int32_t value) {
    return leaf(value + 1);
}

PEELF_EXPORT PEELF_NOINLINE int32_t second(int32_t value) {
    return leaf(value + 2);
}

#if defined(PEELF_SHARED_FIXTURE)
PEELF_EXPORT PEELF_NOINLINE int32_t shared_anchor(int32_t value) {
    puts("peelf shared fixture");
    return first(value) + second(value);
}
#endif

int main(void) {
    const int32_t a = first(10);
    const int32_t b = second(20);
    return (a + b + peelf_cross_sink) == 0 ? 1 : 0;
}
