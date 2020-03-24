# Blind

Poking at this challenge, it becomes clear that we can execute commands on the server, but only receive the exit code of the process. We can use the exit code from `grep`-ing the flag file as an oracle for a bruteforce of the flag. Find the solution script [here](./solve.py).
