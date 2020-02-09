//node 8.12.0
var express = require('express');
var app = express();
var fs = require('fs');
var path = require('path');
var http = require('http');
var pug = require('pug');

app.get('/', function(req, res) {
    res.sendFile(path.join(__dirname + '/index.html'));
});

app.get('/source', function(req, res) {
    res.sendFile(path.join(__dirname + '/source.html'));
});


app.get('/getMeme',function(req,res){
   res.send('<iframe src="https://giphy.com/embed/LLHkw7UnvY3Kw" width="480" height="480" frameBorder="0" class="giphy-embed" allowFullScreen></iframe><p><a href="https://giphy.com/gifs/kid-dances-jumbotron-LLHkw7UnvY3Kw">via GIPHY</a></p>')

});


app.get('/flag', function(req, res) {
    var ip = req.connection.remoteAddress;
    if (ip.includes('127.0.0.1')) {
        var authheader = req.headers['adminauth'];
        var pug2 = decodeURI(req.headers['pug']);
        var x=pug2.match(/[a-z]/g);
        if(!x){
         if (authheader === "secretpassword") {
            var html = pug.render(pug2);
         }
        }
       else{
        res.send("No characters");
      }
    }
    else{
     res.send("You need to come from localhost");
    }
});

app.get('/core', function(req, res) {
    var q = req.query.q;
    var resp = "";
    if (q) {
        var url = 'http://localhost:8081/getMeme?' + q
        console.log(url)
        var trigger = blacklist(url);
        if (trigger === true) {
            res.send("<p>Errrrr, You have been Blocked</p>");
        } else {
            try {
                http.get(url, function(resp) {
                    resp.setEncoding('utf8');
                    resp.on('error', function(err) {
                    if (err.code === "ECONNRESET") {
                     console.log("Timeout occurs");
                     return;
                    }
                   });

                    resp.on('data', function(chunk) {
                        resps = chunk.toString();
                        res.send(resps);
                    }).on('error', (e) => {
                         res.send(e.message);});
                });
            } catch (error) {
                console.log(error);
            }
        }
    } else {
        res.send("search param 'q' missing!");
    }
})

function blacklist(url) {
	console.log(url);
    var evilwords = ["global", "process","mainModule","require","root","child_process","exec","\"","'","!"];
    var arrayLen = evilwords.length;
    for (var i = 0; i < arrayLen; i++) {
        const trigger = url.includes(evilwords[i]);
        if (trigger === true) {
            return true
        }
    }
}

var server = app.listen(8081, function() {
    var host = server.address().address
    var port = server.address().port
    console.log("Example app listening at http://%s:%s", host, port)
})