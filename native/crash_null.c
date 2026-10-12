#include <stdio.h>

int main(void) {
    int *p = NULL;
    printf("about to dereference NULL\n");
    fflush(stdout);
    *p = 42;   /* access violation / SIGSEGV */
    return 0;
}