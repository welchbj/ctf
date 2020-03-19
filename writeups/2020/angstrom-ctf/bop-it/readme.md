# Bop It

Upon inspection of the [provided source](./bop_it.c), we see a potentially vulnerable portion of code:

```c
if (!strcmp(action, actions[3])) {
	char guess[256];
	guess[0] = c;
	int guessLen = read(0, guess+1, 255)+1; //add to already entered char
	guess[guessLen-1] = 0; //remove newline
	char flag[32];
	FILE *f = fopen("flag.txt", "rb");
	int r = fread(flag, 1, 32, f);
	flag[r] = 0; //null terminate
	if (strncmp(guess, flag, strlen(flag))) {
		char wrong[strlen(guess)+35];
		wrong[0] = 0; //string is empty intially
		strncat(wrong, guess, guessLen);
		strncat(wrong, " was wrong. Better luck next time!\n", 35);
		write(1, wrong, guessLen+35);
		exit(0);
	}
}
```

This block of code is hit if the randomly-selected action is `"Flag it"`, which happens 1 in 4 times. Because the flag is loaded into memory, there is a good chance the intended solution is to leak it via the call to `write`.

Because we can control the first byte written into the `guess` buffer, we can write a null-byte. This disrupts any future attempts to find the length of the user input in the `guess` buffer via calls to `strlen`. So, when we send input like `\x00AAAAAAAAAAAAAAAA` into the program, the `wrong` buffer created with `char wrong[strlen(guess)+35]` will only be 35 bytes long, since `strlen("\x00ANYTHING") == 0`. This is paired with another vulnerability in the second `strncat` line, which won't append a null-byte to the `wrong` buffer since the length of its string argument is equal to 35 (its length argument). TLDR [`strncat` is bad](https://eklitzke.org/beware-of-strncpy-and-strncat).

We need our input length to be long enough so the read past the end of the `wrong` buffer picks up the flag. Even though it doesn't look like it, any amount of input past our null byte is still causing the program to read beyond the intended end of `wrong`. This can be verified by piping the program's output to `xxd`. Once we append an input long enough to our first null-byte, eventually we can leak the flag.
