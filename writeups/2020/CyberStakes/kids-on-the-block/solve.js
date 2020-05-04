const Web3 = require('web3');
const InputDataDecoder = require('ethereum-input-data-decoder');

let web3 = new Web3();
web3.setProvider(new web3.providers.HttpProvider('http://localhost:8545'));

const BN = web3.utils.BN;

let START_BLOCK = 0;
let END_BLOCK = 62;
let START_VALUE = new BN('2500000000000000000');

const walletAbi = JSON.parse('[{"constant":true,"inputs":[],"name":"getBalance","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[],"name":"deposit","outputs":[],"payable":true,"stateMutability":"payable","type":"function"},{"constant":false,"inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"name":"withdraw","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"}]');
const walletBytecode = '{"linkReferences":{},"object":"608060405234801561001057600080fd5b50610282806100206000396000f300608060405260043610610057576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806312065fe01461005c578063d0e30db014610087578063f3fef3a314610091575b600080fd5b34801561006857600080fd5b506100716100de565b6040518082815260200191505060405180910390f35b61008f610124565b005b34801561009d57600080fd5b506100dc600480360381019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610172565b005b60008060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054905090565b346000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282540192505081905550565b806000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054101515156101bf57600080fd5b806000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825403925050819055508173ffffffffffffffffffffffffffffffffffffffff166108fc829081150290604051600060405180830381858888f19350505050158015610251573d6000803e3d6000fd5b5050505600a165627a7a7230582082e14bea7d5767c73cadb4112e5c81d459ceeaf6e146fd138e31406d6fc28ea90029","opcodes":"PUSH1 0x80 PUSH1 0x40 MSTORE CALLVALUE DUP1 ISZERO PUSH2 0x10 JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP PUSH2 0x282 DUP1 PUSH2 0x20 PUSH1 0x0 CODECOPY PUSH1 0x0 RETURN STOP PUSH1 0x80 PUSH1 0x40 MSTORE PUSH1 0x4 CALLDATASIZE LT PUSH2 0x57 JUMPI PUSH1 0x0 CALLDATALOAD PUSH29 0x100000000000000000000000000000000000000000000000000000000 SWAP1 DIV PUSH4 0xFFFFFFFF AND DUP1 PUSH4 0x12065FE0 EQ PUSH2 0x5C JUMPI DUP1 PUSH4 0xD0E30DB0 EQ PUSH2 0x87 JUMPI DUP1 PUSH4 0xF3FEF3A3 EQ PUSH2 0x91 JUMPI JUMPDEST PUSH1 0x0 DUP1 REVERT JUMPDEST CALLVALUE DUP1 ISZERO PUSH2 0x68 JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP PUSH2 0x71 PUSH2 0xDE JUMP JUMPDEST PUSH1 0x40 MLOAD DUP1 DUP3 DUP2 MSTORE PUSH1 0x20 ADD SWAP2 POP POP PUSH1 0x40 MLOAD DUP1 SWAP2 SUB SWAP1 RETURN JUMPDEST PUSH2 0x8F PUSH2 0x124 JUMP JUMPDEST STOP JUMPDEST CALLVALUE DUP1 ISZERO PUSH2 0x9D JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP PUSH2 0xDC PUSH1 0x4 DUP1 CALLDATASIZE SUB DUP2 ADD SWAP1 DUP1 DUP1 CALLDATALOAD PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND SWAP1 PUSH1 0x20 ADD SWAP1 SWAP3 SWAP2 SWAP1 DUP1 CALLDATALOAD SWAP1 PUSH1 0x20 ADD SWAP1 SWAP3 SWAP2 SWAP1 POP POP POP PUSH2 0x172 JUMP JUMPDEST STOP JUMPDEST PUSH1 0x0 DUP1 PUSH1 0x0 CALLER PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND DUP2 MSTORE PUSH1 0x20 ADD SWAP1 DUP2 MSTORE PUSH1 0x20 ADD PUSH1 0x0 KECCAK256 SLOAD SWAP1 POP SWAP1 JUMP JUMPDEST CALLVALUE PUSH1 0x0 DUP1 CALLER PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND DUP2 MSTORE PUSH1 0x20 ADD SWAP1 DUP2 MSTORE PUSH1 0x20 ADD PUSH1 0x0 KECCAK256 PUSH1 0x0 DUP3 DUP3 SLOAD ADD SWAP3 POP POP DUP2 SWAP1 SSTORE POP JUMP JUMPDEST DUP1 PUSH1 0x0 DUP1 CALLER PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND DUP2 MSTORE PUSH1 0x20 ADD SWAP1 DUP2 MSTORE PUSH1 0x20 ADD PUSH1 0x0 KECCAK256 SLOAD LT ISZERO ISZERO ISZERO PUSH2 0x1BF JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST DUP1 PUSH1 0x0 DUP1 CALLER PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND DUP2 MSTORE PUSH1 0x20 ADD SWAP1 DUP2 MSTORE PUSH1 0x20 ADD PUSH1 0x0 KECCAK256 PUSH1 0x0 DUP3 DUP3 SLOAD SUB SWAP3 POP POP DUP2 SWAP1 SSTORE POP DUP2 PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND PUSH2 0x8FC DUP3 SWAP1 DUP2 ISZERO MUL SWAP1 PUSH1 0x40 MLOAD PUSH1 0x0 PUSH1 0x40 MLOAD DUP1 DUP4 SUB DUP2 DUP6 DUP9 DUP9 CALL SWAP4 POP POP POP POP ISZERO DUP1 ISZERO PUSH2 0x251 JUMPI RETURNDATASIZE PUSH1 0x0 DUP1 RETURNDATACOPY RETURNDATASIZE PUSH1 0x0 REVERT JUMPDEST POP POP POP JUMP STOP LOG1 PUSH6 0x627A7A723058 KECCAK256 DUP3 0xe1 0x4b 0xea PUSH30 0x5767C73CADB4112E5C81D459CEEAF6E146FD138E31406D6FC28EA9002900 ","sourceMap":"27:525:0:-;;;;8:9:-1;5:2;;;30:1;27;20:12;5:2;27:525:0;;;;;;;"}';

const decoder = new InputDataDecoder(walletAbi);
const graph = {};

function isPossibleValue(value, ceiling) {
    if (value.gt(ceiling) || value.eq(new BN(0))) {
      return false;
    }

    return ceiling.mod(value).eq(new BN(0));
}

function buildGraph() {
  for (let i = START_BLOCK; i <= END_BLOCK; ++i) {
    web3.eth.getBlock(i, true).then(block => {
      if (block == null) {
        return;
      }

      if (block != null && block.transactions != null) {
        block.transactions.forEach(tx => {
          if (tx.to == null) {
            // Contract creation block.
            return;
          }

          toAddr = tx.to.toLowerCase();
          fromAddr = tx.from.toLowerCase();

          if (!(fromAddr in graph)) {
            graph[fromAddr] = [];
          }

          if (!(toAddr in graph)) {
            graph[toAddr] = [];
          }

          value = new BN(tx.value);
          graph[fromAddr].push({dest: toAddr, value: value});

          if (tx.input != null && tx.input != '0x') {
            txInput = decoder.decodeData(tx.input);
            if (txInput.method == 'withdraw') {
              destAddr = '0x' + txInput.inputs[0].toLowerCase();
              value = txInput.inputs[1];  // is a BN

              graph[toAddr].push({
                dest: destAddr,
                value: value,
                fromWithdraw: true
              });
            }
            else if (txInput.method == 'deposit') {
              // Do nothing, since this deposit is already recorded above.
            }
            else {
              console.log('Unknown method ' + txInput.method);
            }
          }
        });
      }
    });
  }
}

function printNode(node) {
    console.log('dest  : ' + node.dest);
    console.log('value : ' + node.value.toString());
}

function followTheMoney(path, ceilingValue) {
  let currAddr = path[path.length - 1];
  let children;

  if (!(currAddr in graph)) {
    console.log('ENCOUNTERED NON-EXISTENT ADDRESS: ' + currAddr);
    return;
  }

  children = graph[currAddr];

  if (children.length == 0) {
    console.log('FOUND VALID PATH:');
    console.log(path);
    return;
  }

  for (let i = 0; i < children.length; ++i) {
    let tx = children[i];

    if (tx.dest == currAddr) {
      continue;
    }

    if (isPossibleValue(tx.value, ceilingValue)) {
      let newPath = path.slice();
      newPath.push(tx.dest);

      console.log('POSSIBLE PATH:');
      console.log('--------------');
      console.log(newPath);
      console.log();

      followTheMoney(newPath, START_VALUE);
    }
  }
}

function analyzeGraph() {
  console.log(graph);
  let path = ['0xb4ba4b90df51d42a7c6093e92e1c7d22874c14f2']
  followTheMoney(path, START_VALUE);
}

setTimeout(analyzeGraph, 2000);
buildGraph();