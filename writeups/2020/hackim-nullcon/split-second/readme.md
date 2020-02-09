# Split Second

## Setup

This was a web challenge that involved exploiting a couple of bugs within a [Node.js](https://nodejs.org/en/) web [server](./server.js).

The server source can be pulled down with a request to the `/source` endpoint, as noted when viewing source of the site's index page.

It is immediately obvious that the goal is to somehow request the `/flag` endpoint from localhost, as this allows us to pass a payload to the [Pug templating engine](https://pugjs.org). Pug is no different than most other server-side templating engines in that reaching code execution through them is fairly trivial.

## Request Splitting

To request the `/flag` endpoint from localhost, we will need some kind of SSRF. The comment indicating the Node version of 8.12.0 (which is quite old) at the top of the [`server.js`](./server.js) file is a give away as to where to begin the search.

Some basic [OSINT](https://hackerone.com/reports/409943) gives us what we are looking for: an [HTTP request splitting vulnerability](https://twitter.com/YShahinzadeh/status/1039396394195451904) for this version of Node. [Node Version Manager](https://github.com/nvm-sh/nvm) is an amazing project that let me set up a matching environment quickly to confirm that this vulnerability applied.

With a SSRF path in hand, we just needed to send a Pug payload. Fortunately, the [`tplmap` project](https://github.com/epinna/tplmap) already has [one](https://github.com/epinna/tplmap/blob/749807616ab1b173827913b325c5974e8f77f3d8/plugins/engines/pug.py#L57).

## Payload Encoding

However, the Pug payload header blacklists all lowercase characters. There is also a blacklist earlier on in the server's request-handling flow to disallow the main keywords (and `!` symbol) that would be used in a typical Pug payload.

To bypass these, I used a [jsfuck](http://www.jsfuck.com/)-inspired set of primitives (neatly organized in [a table on Wikipedia](https://en.wikipedia.org/wiki/JSFuck#Example:_Creating_the_letter_%22a%22)). This gist of the Pug payload is to build up references to the [`String.fromCharCode`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/fromCharCode) function (for encoding the shell exec Pug payload) and [`Function`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function) constructor (for creating and executing a function from a string).

A full solution script is available [here](./solve.py).
