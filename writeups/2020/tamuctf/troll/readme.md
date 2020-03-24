# Troll

After a quick look at this binary in Binary Ninja, looks like we can compute the answer to all of the questions it asks us if we control the `srand` seed. This seed can easily be overwritten to a value we control via a basic stack-based buffer overflow.

Knowing the seed now, we can generate the required stream of random numbers with this C program:

```c
#include <stdio.h>
#include <stdlib.h>

#define SEED (0x42424242)

int main(void) {
    int i;

    srand(SEED);
    for(i = 0; i < 0x64; ++i) {
        printf("%d\n", rand());
    }

    return 0;
}
```

And then store it for consumption by our Python solve script:

```sh
gcc mkrand.c -o mkrand
mkrand > rand.lst
```

Instead of reversing the computations performed on the result of the `rand` call, we can just emulate them with [Unicorn](https://github.com/unicorn-engine/unicorn/tree/master/bindings/python). This is implemented in the solve script [here](./solve.py).

