# Mental Math

This was an interesting web challenge. Inspecting source of the web page shows some partially commented out Python template language, hinting that the server is written in Python.

Messing with the requests a little bit, it becomes clear that the server is essentialy `eval`-ing the expression we send in one parameter and comparing it to our submitted answer in another parameter. We can therefore use this as an oracle to bruteforce the value of each character in the flag file.

Find my solution script [here](./solve.py).
