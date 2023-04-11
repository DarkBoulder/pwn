#include <stdio.h>
#include <stdlib.h>

struct Switcher{
    char* name;
};
int main(){
    struct Switcher *switcher = malloc(0x160);
    switcher->name = malloc(0x160);

    printf("%x, %x\n", switcher, switcher->name);

	return 0;
}
