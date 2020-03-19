# Inputter

This miscellaneous challenge was just an exercise in passing weird values on stdin and as command-line arguments. Not a super difficult challenge, but I'm keeping the solution here for future reference:

```sh
echo -e '\x00\x01\x02\x03' | ./inputter $' \n\'\"\x07'
```
