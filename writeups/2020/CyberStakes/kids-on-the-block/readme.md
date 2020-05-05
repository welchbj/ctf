# Kids on the Block

This was a super interesting challenge that involved tracing transactions through a private [Ethereum blockchain](https://ethereum.org/).

## Getting Set Up

It took me a while to get spun up and figure out how to script the required analysis, but eventually [this blog post](https://arvanaghi.com/blog/testing-smart-contracts-on-a-private-blockchain-with-Geth/) got me on my way. I ended up needing the following ingredients:

* A method of compiling the provided contract. I did this on the online [remix solidity compiler](https://remix.ethereum.org/).
* A method of programmatically interacting with the local blockchain. While `geth` provides some native JavaScript bindings that are pretty good, I eventually graduated to using the [`web3.js`](https://web3js.readthedocs.io/en/v1.2.7/) node package due to the need for other utility JavaScript packages. Note that when using this package, you need to start `geth` with `geth --rpc --rpcapi="eth,web3,personal"`.
* A method of decoding block input data into understandable metadata. I used the [`ethereum-input-data-decoder` node package](https://www.npmjs.com/package/ethereum-input-data-decoder) for this, which worked great.
* Some baseline knowledge on how to process blocks and contracts. [This StackExchange questions](https://ethereum.stackexchange.com/questions/2531/common-useful-javascript-snippets-for-geth) is full of great examples. Most of my core solution code is based on snippets from these answers.
* Not mandatory, but visually inspecting the graph through an [Epirus](https://github.com/blk-io/epirus-free) instance helped me better understand what was going on.

## Performing the Analysis

Setting all of this up was the hard part and took a while, since I knew next to nothing about Ethereum previously. Once I could interact with the blockchain, the analysis was actually fairly straightforward. My strategy was to construct a graph of addresses, with edges representing transactions between blocks(weighted by the transaction value).

Encoding typical to/from Ethereum transactions was pretty simple, but we also need to account for transactions that moved through instances of the provided [wallet contract](./wallet.sol). This just required some inspection of the block input arguments, and could be encoded naturally within the nodes and edges of our graph. Once the graph is constructed, following the money is just a matter of traversing from the start address through all edges that represent a logical fraction of the stolen money.
