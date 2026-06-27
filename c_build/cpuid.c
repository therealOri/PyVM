#include <stdint.h>

#ifdef _WIN32
__declspec(dllexport) void cpuid(uint32_t eax, uint32_t ecx, uint32_t* out) {
    __cpuidex((int*)out, eax, ecx);
}
#else
__attribute__((visibility("default")))
void cpuid(uint32_t eax, uint32_t ecx, uint32_t* out) {
    __asm__ volatile("cpuid"
    : "=a"(out[0]), "=b"(out[1]), "=c"(out[2]), "=d"(out[3])
    : "a"(eax), "c"(ecx));
}
#endif
