// console.log("herhehrehrehhrehreh");

// const NodeRSA = require('node-rsa');
// const key = new NodeRSA({b: 1024});

// var public_key = key.exportKey('public');
// var private_key = key.exportKey('private');
// console.log(public_key + '\n' + private_key);


document.addEventListener('DOMContentLoaded', function(){
        var qrcode = new QRCode(document.getElementById("qrcode"),{
            width: 200,
            height: 200
        });

        qrcode.makeCode("https://www.youtube.com/");

//        var key = new NodeRSA({b: 512});
  //      var text = 'Hello RSA!';
    //    var encrypted = key.encrypt(text, 'base64');

      //  console.console.log(encrypted);
});
