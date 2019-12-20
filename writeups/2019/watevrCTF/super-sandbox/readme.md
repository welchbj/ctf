# Super Sandbox

This was an interesting JavaScript sandbox escape problem. You are given the following sandbox code:
```javascript
let code = location.search.slice(6);

let env = {
    a: (x, y) => x[y],
    b: (x, y) => x + y,
    c: (x) => !x,
    d: []
};

for (let i=0; i<code.length; i+=4) {
    let [dest, fn, arg1, arg2] = code.substr(i, 4);

    let res = env[fn](env[arg1], env[arg2]);

    env[dest] = res;
}
```

I didn't realize this while working on the problem, but this is essentially a [jsfuck](http://www.jsfuck.com/) interpreter. The main goal of the payload I constructed was to execute the following:
```javascript
env['a']([], 'fill')['constructor']('', 'alert(1)')('', '')
```

I eventually built this with a (very) verbose solve script, available [here](./solve.py).
