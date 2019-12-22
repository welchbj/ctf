var db;
var request = indexedDB.open("miner",1);
request.onsuccess = (e) => { 
    db = e.target.result
};
request.onupgradeneeded = (e) => {
    let db = e.currentTarget.result;
    db.createObjectStore('blocks',{keyPath: 'data'});
    db.createObjectStore('rewards',{keyPath: 'flag'});
}

var deploy_key='2d613b486cbb9a01c37498676f325759'

var Module = {
    preRun: [],
    postRun: undefined,
    print: (function() {
        return function(text) {
            if (arguments.length > 1) text = Array.prototype.slice.call(arguments).join(' ');
            console.log(text);
        }
    })(),
    printErr: function(text) {
        if (arguments.length > 1) text = Array.prototype.slice.call(arguments).join(' ');
        console.error(text);
    },
    totalDependencies: 0,
    noExitRuntime: true,
};
self.importScripts('miner.js')
