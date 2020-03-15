# Little Engine

We can identify the good and bad character check code paths that occur towards the end of the execution flow, and trace when they get hit with some GDB scripting. We can then use this trace as an oracle for brute-forcing inputs that hit the good check code path.

Find the solution script [here](./solve.py).
