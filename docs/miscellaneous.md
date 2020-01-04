# Miscellaneous

Where the other stuff doesn't fit.

## C/C++ Preprocessor Hacks

A fun class of CTF problems involving C/C++ compiler preprocessor abuse.

### Primitives

Mainstream C compilers provide more preprocessing functionality than they initially let on. Note: this section was written only with GCC and Clang in mind.

#### Compiler Flags and Builtin Macros

Since most of these techniques require abusing preprocessor macros, the `-E` flag from GCC/Clang will be your friend. This flag will cause only the preprocessor stage to be run, showing the generated C source after all subsitutions have been performed.

When first starting a challenge, you may also want to gather some information about the version of the compiler in use. Below are some potentially useful version/compiler-related macros. GCC's full list can be found [here](https://gcc.gnu.org/onlinedocs/cpp/Common-Predefined-Macros.html#Common-Predefined-Macros) and Clang's [here](https://clang.llvm.org/docs/LanguageExtensions.html#builtin-macros).

| Macro                  | Meaning                                                          |
| ---------------------- | ---------------------------------------------------------------- |
| `__clang__`            | Defined if Clang is the compiler                                 |
| `__clang_major__`      | Clang major version                                              |
| `__clang_minor__`      | Clang minor version                                              |
| `__clang_patchlevel__` | Clang patchlevel                                                 |
| `__clang_version__`    | Clang marketing verson                                           |
| `__GFORTRAN__`         | Defined by the GNU Fortran compiler                              |
| `__GNUC__`             | Major version defined by GNU C/C++/Objective-C/Fortran compilers |
| `__GNUC_MINOR__`       | Minor version defined by GNU C/C++/Objective-C/Fortran compilers |
| `__GNUC_PATCHLEVEL__`  | Patchlevel defined by GNU C/C++/Objective-C/Fortran compilers    |
| `__GNUG__`             | Defined by the GNU C++ compiler                                  |
| `__ELF__`              | Defined if ELF is the target executable format                   |

Additionally, there are some "base" macros that give you a better idea about things like where you are in the file system.

| Macro               | Meaning                                                          |
| ------------------- | ---------------------------------------------------------------- |
| `__BASE_FILE__`     | The name of the main input file                                  |
| `__FILE__`          | Absolute path to the file being processed                        |
| `__FILE_NAME__`     | Similar to `__FILE__`, but just the file's name                  |
| `__COUNTER__`       | Counter that increments by 1 each time it is expanded            |
| `__INCLUDE_LEVEL__` | Include depth of the current file; starts at 0 for the main file |
| `__TIMESTAMP__`     | Date/time of current source file's last modification time        |

#### Digraphs and Trigraphs

Some challenges will introduce bad character restrictions for macro/syntax-related characters (`{`, `}`, `#`, etc.). Fortunately, the mainstream C/C++ compilers support [digraphs and trigraphs](https://en.wikipedia.org/wiki/Digraphs_and_trigraphs), which allow you to encode these special characters in other ways. Some of the useful ones include:

| Digraph / Trigraph | Resolves to |
| ------------------ | ----------- |
| `<:`               | `[`         |
| `:>`               | `]`         |
| `<%`               | `{`         |
| `%>`               | `}`         |
| `%:`               | `#`         |
| `%:%:`             | `##`        |
| `??=`              | `#`         |
| `??/`              | `\`         |
| `??'`              | `^`         |
| `??(`              | `[`         |
| `??)`              | `]`         |
| `??!`              | `|`         |
| `??<`              | `{`         |
| `??>`              | `}`         |
| `??-`              | `~`         |

Additionally, the [C alternative tokens](https://en.wikipedia.org/wiki/C_alternative_tokens) may be helpful in these types of problems. While these can be used without additional include files as per the C++ standard, they may require the inclusion of the `iso646.h` header for C programs. The tokens are:

| Token    | Equivalent to |
| -------- | ------------- |
| `and`    | `&&`          |
| `and_eq` | `&=`          |
| `bitand` | `&`           |
| `bitor`  | `|`           |
| `compl`  | `~`           |
| `not`    | `!`           |
| `not_eq` | `!=`          |
| `or`     | `||`          |
| `or_eq`  | `|=`          |
| `xor`    | `^`           |
| `xor_eq` | `^=`          |

From simple experimentation and [a StackOverflow post](https://stackoverflow.com/questions/30167102/why-does-gcc-emit-a-warning-when-using-trigraphs-but-not-when-using-digraphs#30167351), it appears that GCC/Clang will emit a warning when trigraphs are in use, but accept bigraphs without issue. Your mileage may vary.

#### Suppressing Errors

Both GCC and Clang support macros for ignoring different classes of warnings and errors. Below are some snippets demonstrating this.

Disabling all warnings:
```c
_Pragma("GCC diagnostic ignored \\"-Weverything\\"");
// or (s/clang/GCC)
#pragma clang diagnostic ignored "-Weverything"
```

Force something to be a warning (even with `-Werror` enabled):
```c
#pragma GCC diagnostic warning "-Wuninitialized"
```

#### `__has_include` and Friends

You don't always know what file you need to read. To quickly check a lot of candidate file names, the `__has_include` and `__has_include_next` macros are nice tools ([GCC docs](https://gcc.gnu.org/onlinedocs/cpp/_005f_005fhas_005finclude.html) and [Clang docs](https://clang.llvm.org/docs/LanguageExtensions.html#include-file-checking-macros)).

`__has_include` can be used to selectively include files that actually exist in the following way:
```c
#if __has_include("/some/file/1")
    #include "/some/file/1"
#endif

#if __has_include("/some/file/2")
    #include "/some/file/2"
#endif
```

#### Stringification

It is possible to coerce file contents into a C string array, which is a useful primitive for more advanced compile time logic. There are couple of ways to do it. The two below examples are working in the following environment:

* The flag is located in the `flag.txt` file
* The flag prefix is known to be `flag_prefix`
* The flag file contents are `flag_prefix{flag_contents_here}`

The first technique involves using macro string coercion:
```c
void wrapper() {
#define char_array(x) const char flag_string[] = x;
#define to_string(x) char_array(#x)
#define flag_prefix to_string(
#include "flag.txt"
)
}

// this produces the following C source:
void wrapper() {
const char flag_string[] = "{flag_contents_here}";
}
```

Here's another similar technique, which uses `__VA_ARGS__` with macro string coercion.
```c
void wrapper() {
#define to_str(...) (#__VA_ARGS__)
#define flag_prefix to_str(
const char flag_string[] =
#include "flag.txt"
);
}

// this produces the following C source:
void wrapper() {
const char flag_string[] =
("{flag_contents_here}");
}
```

### Error Code Oracles

Full file content disclosure does not even require output reflection from the vulnerable service as long as you are able to retrieve the error code from the compilation process. This was demonstrated in the [compilerbot](https://ctftime.org/task/10196) challenge from HXP 36C3 CTF 2019.

The first technique we'll examine (introduced in [this compilerbot writeup](https://github.com/tmr232/writeups/tree/master/hxp-36c3-ctf/compilerbot)). Once the length of the flag is known, each character from the flag's contents can be used to index a separate varying-length array. If we modify the length of the varying-length array until it would go out of bounds when accessing the array, we will learn the value of the character at the tested index of the flag. Here is a basic implementation would show one iteration of the attack:
```c
#pragma clang diagnostic ignored "-Wchar-subscripts"
#pragma clang diagnostic ignored "-Wunused-variable"
#pragma clang diagnostic fatal "-Warray-bounds-pointer-arithmetic"

void wrapper() {
#define to_str(...) (#__VA_ARGS__)
#define flag_prefix to_str(

#define TEST_LENGTH 100
#define TEST_INDEX 0

const char test_array[TEST_LENGTH] = {0};
const char c = test_array[
#include "flag.txt"
)[TEST_INDEX]];
}

int main() {
    wrapper();
}

// this produces the following C source:
void wrapper() {
const char test_array[100] = {0};
const char c = test_array[
("{flag_contents_here}")[0]];
}

int main() {
    wrapper();
}
```

Another techinque involves abusing duplicate cases in switch statements to generate errors based on the value of an expression. This method comes from [this compilerbot writeup](https://github.com/OmerYe/ctf-writeups/blob/master/2019/36c3/compilerbot-solve.py). A basic implementation of this technique follows:
```c
void wrapper() {
#define to_str(...) (#__VA_ARGS__)
#define flag_prefix to_str(

const char flag_string[] =
#include "flag.txt"
);

#define COMPILE_TIME_ASSERT(EXPR) switch (0){case 0: case (EXPR):;}
// compilation fails when the character test is false/0, as this generates
// a duplicate 0 case in the above switch statement; consequently, when
// no error occurs, we have found the correct flag character at the tested
// index
COMPILE_TIME_ASSERT(flag_string[0] == '{');
}

int main() {
    wrapper();
}
```

A bit more involved than the previous two methods, the `.incbin` assembler directive can be used. RPISEC has published [an awesome writuep](https://rpis.ec/blog/hxp-26c3-ctf-compilerbot/) which explores this method. The gist of their solution is to use `.incbin` to test different characters of the flag contents in one of the ELF header sections, causing a linkage error to be printed. A nice bonus of this technique is that variations of it can work with both Clang and GCC.
