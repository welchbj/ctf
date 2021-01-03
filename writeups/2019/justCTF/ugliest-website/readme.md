# Ugliest Website

This was an awesome challenge covering data exfiltration CSS injection. I didn't solve it during the competition, but put it together afterwords as a training exercise.

The gist of the challenge / solution flow is:

* We need to exfiltrate the admin/judge's timestamp and 64-character API token (the UID is always 1)
* All exfiltration must spawn from a single previously-uploaded CSS file; it's not possible to recursively `@import` new style sheets due to the nonce-based CSP for CSS (but I like having this idea in the back pocket for future CTFs)
* I think a font-ligature attack with scrollbar side channel MIGHT be possible but... I didn't feel like generating all of the WOFF fonts
* It is possible to use CSS animations + CSS variables + regex selectors to leak all three-character sub-sets of the admin's 64 character token (this length could be more without the 500kb CSS file upload size limit)

I took this opportunity to brush up on server/client writing with [`aiohttp`](https://aiohttp.readthedocs.io/en/stable/). The rough [solve script](./solve.py) that I wrote after the competition is included in this directory.

Some great resources I read over while working on this:

* [Scriptless attacks -- Stealing the pie without touching the sill](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.469.7647&rep=rep1&type=pdf)
* [CSS injection primitives](https://x-c3ll.github.io/posts/CSS-Injection-Primitives/)
* [CSS injection attacks](https://vwzq.net/slides/2019-s3_css_injection_attacks.pdf)
* [Exfiltration via CSS injection](https://medium.com/bugbountywriteup/exfiltration-via-css-injection-4e999f63097d)
* [Stealing data with CSS](https://www.mike-gualtieri.com/posts/stealing-data-with-css-attack-and-defense)
* [Slackers thread](https://old.reddit.com/r/Slackers/comments/dzrx2s/what_can_we_do_with_single_css_injection) discussing what you can do with a single CSS injection

I plan on reading up on the following topics to better optimize future solutions to similar problems:

* [DNA sequence assembly problem](https://cs.stackexchange.com/questions/93815/merge-a-set-of-strings-based-on-overlaps)
* [De novo sequence assemblers](https://en.wikipedia.org/wiki/De_novo_sequence_assemblers)
