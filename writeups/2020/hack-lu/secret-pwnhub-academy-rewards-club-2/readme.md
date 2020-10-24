# Secret Pwnhub Academy Rewards Club 2

## Solution

The solution requires forcing some SPARC register windows to be flushed onto the stack, and then messing with recursive function calls to position our stack overflow to overwrite one of the flushed return pointers (now saved on the stack instead of a register window).

This solution isn't great, since it relies on returning to a static stack address, but it's good enough.

## Resources

* [Short and sweet SPARC syscall ABI reference](https://unix4lyfe.org/hello-sparc/)
* [Lecture notes discussing recursive function calls in SPARC](http://www.mathcs.emory.edu/~cheung/Courses/255/Syllabus/8-SPARC/recursion.html)
* [More lecture notes discussing the `save`/`restore`/register window concepts of SPARC](http://www.mathcs.emory.edu/~cheung/Courses/255/Syllabus/8-SPARC/save+restore.html)
* [Another nice register window resource](https://docs.rtems.org/releases/rtemsdocs-4.10.2/share/rtems/html/cpu_supplement/cpu_supplement00193.html)
* [A really helpful StackOverflow answer regarding stack exploitation in SPARC](https://security.stackexchange.com/questions/81726/are-sun-oracles-sparc-processors-invulnerable-to-buffer-overrun-exploits)
