/*
 * Test for PC-guard leak prevention on dlopen/dlclose cycles.
 * Compile with: gcc -o test_guard_leak test_guard_leak.c -ldl
 * Run with: HFUZZ_COV_DEBUG=1 LD_PRELOAD=./libhfuzz/libhfuzz.so ./test_guard_leak ./some_instrumented.so
 */
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <instrumented_library.so>\n", argv[0]);
        return 1;
    }

    const char* libpath = argv[1];
    
    printf("Testing guard leak prevention with: %s\n", libpath);
    printf("Watch for 'Reusing guards' messages on iterations 2+\n\n");

    for (int i = 0; i < 5; i++) {
        printf("=== Iteration %d: dlopen ===\n", i + 1);
        void* handle = dlopen(libpath, RTLD_NOW);
        if (!handle) {
            fprintf(stderr, "dlopen failed: %s\n", dlerror());
            return 1;
        }
        
        printf("=== Iteration %d: dlclose ===\n", i + 1);
        dlclose(handle);
    }

    printf("\nIf fix works: 'Reusing guards' should appear on iterations 2-5\n");
    printf("If leaking: guard count increases each iteration\n");
    return 0;
}

