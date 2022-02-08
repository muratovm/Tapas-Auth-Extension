var debug = true;
//Add required libraries
var NodeRSA=require('node-rsa');
var Cryptr = require('cryptr');
var CryptoJS = require("crypto-js");
var crypto = require("crypto");
var yub = require('yubikey-client');


var pad = require ("crypto-js/pad-iso10126");

//Crete and store the asymmetric key
const options = {
  environment: "browser",
  encryptionScheme:"pkcs1_oaep",
  signingScheme:"pkcs1-sha1"
}

var key = new NodeRSA({b: 1024}, options);
const public_key = key.exportKey('public');
const private_key = key.exportKey('private');
chrome.storage.sync.set({"ppk": public_key});
chrome.storage.sync.set({"prk": private_key});

/* CORRECT WAY TO ENCODE AND DECODE BASE64
var encrypted = CryptoJS.AES.encrypt("Message", "Secret Passphrase");
var base64Value = encrypted.toString();
var encryptedText = CryptoJS.enc.Base64.parse(base64Value)
var encrypted2 = encryptedText.toString(CryptoJS.enc.Base64);
var decrypted = CryptoJS.AES.decrypt(encrypted2, "Secret Passphrase");
var decoded_str = decrypted.toString(CryptoJS.enc.Utf8)
alert(decoded_str);
*/

//Crete and store the master key
//var key2 = new NodeRSA({b: 512});
//var master_key = key2.exportKey('private');
chrome.storage.sync.get(['masterKey'], function(master_K) {  
  if(master_K == null){
    // alert("exists");
  }
  else{
    // alert("fdfd");
    master_key = "masterkey";
    chrome.storage.sync.set({"masterKey": master_key});
  }
});

// chrome.storage.sync.get(['masterKey'], function(master_K2) {
//   alert("master: " + master_K2.masterKey);
// });
//Crete and store the recovery key
//var key3 = new NodeRSA({b: 512});
//var recovery_key = key3.exportKey('private');

chrome.storage.sync.get(['recoveryKey'], function(recover_K) {  
  if(recover_K == null){
    //alert("exists")
  }
  else{
    recovery_key = "recovery_key";
    chrome.storage.sync.set({"recoveryKey": recovery_key});
  }
});


//Initilize the required variables 
var iv  = CryptoJS.lib.WordArray.random(16);
let pass;
var counter = 0;
var qrcode;


// alert("IV " + iv);
// alert("IV 64 " + CryptoJS.enc.Base64.parse(iv.toString()));


//Reques the aes symmetric key from the user
const request = async(token)=>{
  const response  = await fetch('https://web20200225074505.azurewebsites.net/Api/Credential/Aes/' + token, {method: 'GET'}).then(r => r.text()).then(result2 => {
    //Fetch the private key from storage
    chrome.storage.sync.get(['prk'], function(private) {      
    
    //Decrypt the symmetric key using the private key
    const key_pr2 = new NodeRSA(private.prk);
    try{
    var plaintext = key_pr2.decrypt(result2, 'utf8');
    //alert(plaintext)
    chrome.storage.sync.set({"symmetricKey": plaintext});
    if(debug){
      alert("Passphrase from phone for AES: "+plaintext)
    }
    }
    catch(err){
      alert(err)
    }
});
});
}

//Pair button handler
document.getElementById("PairBtn").addEventListener("click", async function(){
  
  //Request connection token from the server
  await fetch('https://web20200225074505.azurewebsites.net/Api/Credential/', {method: 'GET'}).then(r => r.text()).then(result => {
    pass = result;
    //Wait to recieve the connection token before proceeding 
    function sleep (seconds) {
          var start = new Date().getTime();
          while (new Date() < start + seconds*1000) {}
          return 0;
      }
    
    sleep(0.005);
    pass = result;

    //If this is the first phone being paired set recovery to false else set recovery to true
    chrome.storage.sync.get(['connectionToken'], function(data) {
      if (typeof data.connectionToken != 'undefined') {
        chrome.storage.sync.set({"recoveryFlag": true});
      }

      else{
        chrome.storage.sync.set({"recoveryFlag": false});
      }
  });

    //Store the connection token in chrome storage
    chrome.storage.sync.set({"connectionToken": result});

    //If the QRCode has never been made yet make it 
    if(counter == 0){
      qrcode = new QRCode(document.getElementById("qrcode"),{
      width: 200,
      height: 200
    });
    counter ++;
    }
  
  //Fetch the token and public from storage 
  chrome.storage.sync.get(['connectionToken'], function(result) {      
    chrome.storage.sync.get(['ppk'], function(public) {      

        //Create json file that includes the token and public key
        var qrcodeContent = {"Token": result.connectionToken, "PublicKey": public.ppk};
        var qrcodeContentJSON = JSON.stringify(qrcodeContent);

        //Create the qrcode
        qrcode.makeCode(qrcodeContentJSON);
    });
   });
  });

    //Display qrcode to the user
    document.getElementById("qrcode").style.visibility = "visible";
});

//Get credentials button handler
document.getElementById("GetCredentialsBtn").addEventListener("click", function(){
  //Fetch the token from storage and request the symmetric key from the phone
        //If this is the first phone beinf paired set recovery to false else set recovery to true
        chrome.storage.sync.get(['symmetricKey'], function(data) {
          if (typeof data.connectionToken == 'undefined') {
            chrome.storage.sync.get(['connectionToken'], function(connectionT) {  
              request(connectionT.connectionToken);
            });
          }
      });

      //Get the domain name of the current tab
      chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        var tab = tabs[0];
        var url = new URL(tab.url);
        var domain = url.hostname;
        if(debug){
          alert("Using Domain: "+url.hostname)
        }
      //Fetch the token and symmetric key from storage
      chrome.storage.sync.get(['connectionToken'], function(connectionT2) {  
        chrome.storage.sync.get(['symmetricKey'], function(symmetric_k) {  

          var password = symmetric_k.symmetricKey;
          var salt =  CryptoJS.enc.Utf8.parse("12345678");
          var keyBits = CryptoJS.PBKDF2(password, salt, {
            hasher: CryptoJS.algo.SHA1,
            keySize: 8,
            iterations: 2048
          });
          
          try{
          var iv = CryptoJS.lib.WordArray.random(16);
          var options = { iv:iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7};
          var encrypted_domain = CryptoJS.AES.encrypt(domain, keyBits, options);
          var GetCredentials = {"IV":  CryptoJS.enc.Base64.stringify(iv), "Ciphertext": encrypted_domain.ciphertext.toString(CryptoJS.enc.Base64)};
          var GetCredentialsJSON = JSON.stringify(GetCredentials);
          var string = GetCredentialsJSON.split("\"").join("\'")
          string =  "\""+ string+"\""
          if(debug){
            alert("Encrypted Domain: "+string)
          }
        }
        catch(err){
          alert(err)
        }

          fetch('https://web20200225074505.azurewebsites.net/Api/Credential/Request/' + connectionT2.connectionToken, {method: 'POST', headers: {'Content-Type': 'application/json'},
          body: string}).then(r => r.text()).then(result3 => {
            //Decrypt the received message using the symmetric key and Iv value
          
          if(debug){
            alert("Encrypted Credentials: "+result3)
          }
          var json = JSON.parse(result3)
          var phoneiv = json["IV"]; 
          var ciphertext = json["Ciphertext"]

          var decrypted = CryptoJS.AES.decrypt(ciphertext, keyBits, {
            iv: CryptoJS.enc.Base64.parse(phoneiv),
            padding: CryptoJS.pad.Pkcs7,
            mode: CryptoJS.mode.CBC
          });
        
          //Fetch master key from tstorage
          chrome.storage.sync.get(['masterKey'], function(master_K) {  
              //Decrypt user credentials using the master key
              var decryptedjson = JSON.parse(decrypted.toString(CryptoJS.enc.Utf8))
              if(debug){
                alert("Decrypted AES Message: "+JSON.stringify(decryptedjson))
              }
              try{
              var encrypteduser = CryptoJS.enc.Base64.parse(decryptedjson["user_name"])
              var encryptedpass =  CryptoJS.enc.Base64.parse(decryptedjson["password"])
              
              var str_user = encrypteduser.toString(CryptoJS.enc.Base64);
              var str_pass = encryptedpass.toString(CryptoJS.enc.Base64);
              
              var userName = CryptoJS.AES.decrypt(str_user,master_K.masterKey).toString(CryptoJS.enc.Utf8);
              var userpassword = CryptoJS.AES.decrypt(str_pass,master_K.masterKey).toString(CryptoJS.enc.Utf8);
              alert("Username: "+userName+"   Password: "+userpassword);
            }
            catch(err){
              alert(err)
            }
              //Store user credentials in chrome storage
              chrome.storage.sync.set({"curr_username": userName});              
              chrome.storage.sync.set({"curr_password": userpassword});
            });
          })
      });
  });

  });
});


//Create new credential button handler
document.getElementById("CreateCredentialsBtn").addEventListener("click", function(){ 
//Fetch the token from storage and request the symmetric key from the phone
chrome.storage.sync.get(['symmetricKey'], function(data) {
  if (typeof data.connectionToken == 'undefined') {
    chrome.storage.sync.get(['connectionToken'], function(connectionT) {  
      request(connectionT.connectionToken);
    });
  }
});
});


//Create new credential submit button handler
document.getElementById("submitBtn").addEventListener("click", function(){ 
  // alert("fdskjgnksmfnlksdm flds fds,.f");
  //Fetch the master key from storage
  chrome.storage.sync.get(['masterKey'], function(master_K) {  
    if(master_K != null){
      alert("exists");
    }

    //Encrypt the user credentials using the master key

    if(debug){
      alert("Username: "+document.getElementById("username").value+"  Password: "+document.getElementById("password").value)
    }
    var encrypt_username = CryptoJS.AES.encrypt(document.getElementById("username").value, master_K.masterKey);
    var encrypt_password = CryptoJS.AES.encrypt(document.getElementById("password").value, master_K.masterKey);


    var base64_username = encrypt_username.toString();
    var base64_password = encrypt_password.toString();

    if(debug){
      alert("Username: "+base64_username+"  Password: "+base64_password)
    }

    try{
    //Store user encrypted credentials in json format
    var credentials = {"user_name": base64_username, "password": base64_password};
    var credentialsJSON = JSON.stringify(credentials);

    if(debug){
      alert("Encrypted Credentials: "+credentialsJSON)
    }
    }
    catch(err){
      alert(err)
    }
    // alert("before the dommain");

    //Find and store the current tab's domain name
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      var tab = tabs[0];
      var url = new URL(tab.url);
      var create_domain = url.hostname;

      // alert("after domain");
      //Fetch the token, symmetric key and recovery key from storage
      chrome.storage.sync.get(['connectionToken'], function(result4) {   
        chrome.storage.sync.get(['symmetricKey'], function(symmetric_k3) {   
          chrome.storage.sync.get(['OTP'], function(otp) {   

            //create the ciphertext json
            var cipher = {"Domain": create_domain, "Credential": credentialsJSON};
            var cipherJSON = JSON.stringify(cipher);
            // alert("cipherJSON : " + cipherJSON);
            
            if(debug){
              alert("Message to the Phone: "+cipherJSON)
            }

            // alert(" key_B -> : " + key_B.New_recover);
            

            var options1 = {mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7};
            var password1 = otp.OTP;
            var salt1 =  CryptoJS.enc.Utf8.parse("12345678");
            var keyBits1 = CryptoJS.PBKDF2(password1, salt1, {
              hasher: CryptoJS.algo.SHA1,
              keySize: 8,
              iterations: 2048
            });

            //Encrypted data for recovery  
            var encrypt_createCredentialsJSON_recovery = CryptoJS.AES.encrypt(cipherJSON, keyBits1, options1);
            var createCredentials_recovery = {'Ciphertext': encrypt_createCredentialsJSON_recovery.ciphertext.toString(CryptoJS.enc.Base64)};
            var createCredentials_recoveryJSON = JSON.stringify(createCredentials_recovery);
            var recoverystring = createCredentials_recoveryJSON.split("\"").join("\'");
            recoverystring =  "\""+ recoverystring+"\"";

            // alert("afterrrrr");
            try{
            var password = symmetric_k3.symmetricKey;
            var salt =  CryptoJS.enc.Utf8.parse("12345678");
            var keyBits = CryptoJS.PBKDF2(password, salt, {
              hasher: CryptoJS.algo.SHA1,
              keySize: 8,
              iterations: 2048
            });

            if(debug){
            alert("Passphrase from phone for AES: "+symmetric_k3.symmetricKey)
            //alert("Generated AES key: "+CryptoJS.enc.Base64.stringify(keyBits.toString()))
            }
          
            var iv = CryptoJS.lib.WordArray.random(16);
            var options = { iv:iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7};
            var encrypt_cipherJSON = CryptoJS.AES.encrypt(cipherJSON, keyBits, options);
            var createCredentials = {"IV":  CryptoJS.enc.Base64.stringify(iv), "Ciphertext": encrypt_cipherJSON.ciphertext.toString(CryptoJS.enc.Base64)};
            var createCredentialsJSON = JSON.stringify(createCredentials)
            var string = createCredentialsJSON.split("\"").join("\'")
            string =  "\""+ string+"\""
            if(debug){
              alert("Encrypted with AES: "+createCredentialsJSON)
              }
            
            }
            catch(err){
              alert("Error"+err)
            }

            fetch('https://web20200225074505.azurewebsites.net/Api/Credential/' + result4.connectionToken, {method: 'POST', headers: {'Content-Type': 'application/json'},
            body: string}).then(r => r.text()).then(result3 => {
              alert(result3)
        });
        fetch('https://web20200225074505.azurewebsites.net/Api/Credential/' + result4.connectionToken,
         {method: 'PUT', headers: {'Content-Type': 'application/json'}, body: recoverystring}).then(r => r.text()).then(result5 => {
          alert("alerttttttt 55555:  " + result5);
    });
  });
    
    });
  });
});
    });
  });


//Register yubikey button handler
document.getElementById("RegisterYubiBtn").addEventListener("click", function(){ 
    //Fetch the token from storage and request the symmetric key from the phone
    chrome.storage.sync.get(['symmetricKey'], function(data) {
      if (typeof data.connectionToken == 'undefined') {
        chrome.storage.sync.get(['connectionToken'], function(connectionT) {  
          request(connectionT.connectionToken);
        });
      }
  });
  alert("Please Insert The Yubikey");
});

//Recovery button handler
document.getElementById("RecoveryBtn").addEventListener("click", function(){ 
    //Fetch the token from storage and request the symmetric key from the phone
    chrome.storage.sync.get(['symmetricKey'], function(data) {
      if (typeof data.connectionToken == 'undefined') {
        chrome.storage.sync.get(['connectionToken'], function(connectionT) {  
          request(connectionT.connectionToken);
        });
      }
  });
  alert("Please Insert The Yubikey");
});


//regester the yubikey and store the values
document.getElementById("submitRegYubiBtn").addEventListener("click", function(){ 
    //Get the user input for yubikey credencials and store them in chrome storage
  chrome.storage.sync.set({"OTP": document.getElementById("OTPText").value});

  // alert("otp: " + document.getElementById("OTPText").value);
  // var password = document.getElementById("OTPText").value;
  // var salt =  CryptoJS.enc.Utf8.parse("12345678");
  // var keyBits = CryptoJS.PBKDF2(password, salt, {
  //   hasher: CryptoJS.algo.SHA1,
  //   keySize: 8,
  //   iterations: 2048
  // });

// alert("keyBits " + keyBits);
//   chrome.storage.sync.set({"New_recover": keyBits});



});





//Recovery submit button handler 
// document.getElementById("submitBtn2").addEventListener("click", function(){ 
// //Fetch the recovery flag from chrome storage to ensure recovery could be made
//   chrome.storage.sync.get(['recoveryFlag'], function(recovery_result2) {  
//       //If recovery is possible    
//     if((recovery_result2.recoveryFlag) == true){
//         //Fetch the yubikey credentials and token from storage
//           chrome.storage.sync.get(['clientID'], function(c_ID) {   
//             chrome.storage.sync.get(['SecretKey'], function(secret_k) {  
//             chrome.storage.sync.get(['connectionToken'], function(result5) {   

//               ///send the server the yubikey information and the OTP for verification
//               var formData = new FormData();
//               formData.append('ClientId', c_ID.clientID);
//               formData.append('ApiKey', secret_k.SecretKey);
//               formData.append('Opt', document.getElementById("OTPText").value);
//               /*
//               fetch('https://web20200225074505.azurewebsites.net/Api/Credential/DEV-TEST', {method: 'GET', headers: {'Content-Type': 'application/json',},
//               body: formData,}).then(r => r.text()).then(result4 => {
                    
//                 alert("result4 " + result4);
//                 */
//                 //If the yubikey is successfully verified then proceed
//                 var result4 = "Successful"
//                 if(result4 == "Successful"){
//                   fetch('https://web20200225074505.azurewebsites.net/Api/Credential/' + result5.connectionToken, {method: 'GET'}).then(r => r.text()).then(result6 => {
//                     //alert(result6)

                    
//                       //Fetch the recoveryKey, symmetricKey, and connectionToken from chrome storage
//                       chrome.storage.sync.get(['recoveryKey'], function(recovery_k2) {   
//                         chrome.storage.sync.get(['masterKey'], function(master_K) {   
//                           chrome.storage.sync.get(['connectionToken'], function(result_r) {   
                            
                    
//                     var myStringArray = JSON.parse(result6)
//                     var arrayLength = myStringArray.length;
//                     for (var i = 0; i < arrayLength; i++) {
//                             //Decrypt the recovered ciphertext data 
//                             // youll end with {"Domain": domain, "Credential": credentialsJSON}; where Credential is encrypted using the master_key
                            
//                           try{
//                             var input = myStringArray[i]
//                             input = input.split("\'").join("\"")
//                             var credentialjson =  JSON.parse(input)
//                             if(debug){
//                               alert("Encrypted Ciphertext from Server: "+JSON.stringify(credentialjson))
//                             }
//                             var ciphertext = credentialjson["Ciphertext"]
//                             var encryptedText = CryptoJS.enc.Base64.parse(ciphertext)
//                             var encrypted2 = encryptedText.toString(CryptoJS.enc.Base64);
//                             var decrypted = CryptoJS.AES.decrypt(encrypted2, recovery_k2.recoveryKey);
//                             var decryptedstr = decrypted.toString(CryptoJS.enc.Utf8)
//                             decryptedstr = decryptedstr.split("\\\"").join("\'")
//                             decryptedstr = decryptedstr.split("\\n").join("")
//                             var json = JSON.parse(decryptedstr);
                            
//                             var newjson = json['Credential'].split("\'").join("\"")
//                             var credentialjson = JSON.parse(newjson)

//                             if(debug){
//                               alert("Credentials Message encrypted with recovery: "+JSON.stringify(credentialjson))
//                             }

//                             encryptedText = CryptoJS.enc.Base64.parse(credentialjson['user_name'])
//                             encrypted2 = encryptedText.toString(CryptoJS.enc.Base64);
//                             decrypted = CryptoJS.AES.decrypt(encrypted2, master_K.masterKey);
          
//                             var a = decrypted.toString(CryptoJS.enc.Utf8)
                          
//                             encryptedText = CryptoJS.enc.Base64.parse(credentialjson['password'])
//                             encrypted2 = encryptedText.toString(CryptoJS.enc.Base64);
//                             decrypted = CryptoJS.AES.decrypt(encrypted2, master_K.masterKey);
//                             var b = decrypted.toString(CryptoJS.enc.Utf8)
//                             alert("Username: "+a+"  Password: "+b)
//                             }
//                             catch(err){
//                               alert(err)
//                             }
//                             /*
//                             //Encrypt the {"Domain": domain, "Credential": credentialsJSON} using the AES key
//                             var encrypt_cipher = CryptoJS.AES.encrypt(decrypted_cred, CryptoJS.enc.Base64.parse(symmetric_k4.symmetricKey), { iv: CryptoJS.enc.Base64.parse(iv.toString()), 
//                               mode: CryptoJS.mode.CBC,
//                               padding: CryptoJS.pad.ISO10126PADDIN
//                             });

//                             //Save the used IV and the encrypted {"Domain": domain, "Credential": credentialsJSON} into a json file
//                             var createCredentials2 = {"IV": iv, "Ciphertext": encrypt_cipher};
//                             var createCredentialsJSON2 = JSON.stringify(createCredentials2);

//                             //Send data to the phone 
//                           fetch('https://web20200225074505.azurewebsites.net/Api/Credential/' + result_r.connectionToken +'/' + createCredentialsJSON2, {method: 'POST', headers: {'Content-Type': 'application/json',},
//                           body: createCredentialsJSON2,}).then(r => r.text()).then(result_r2 => {
//                               function sleep (seconds) {
//                                 var start = new Date().getTime();
//                                 while (new Date() < start + seconds*1000) {}
//                                 return 0;
//                               }
                          
//                               sleep(0.05); 
//                           });*/
//                     }
//                         });
//                         });
//                       });
//                   });
//                 }
//           //});
//         });
//         });
//           });
//     }
// });
// });

window.onload=function(){ 
    //When GetCredentialsBtn fetch the connection token and request the symmetric key from the phone
    document.getElementById('GetCredentialsBtn').addEventListener('click',function(){
      chrome.storage.sync.get(['symmetricKey'], function(data) {
        if (typeof data.connectionToken == 'undefined') {
          chrome.storage.sync.get(['connectionToken'], function(connectionT) {  
            request(connectionT.connectionToken);
          });
        }
    });
    chrome.tabs.query({}, function(tabs) {
      for(var i = 0; i < tabs.length; i++) {
      chrome.tabs.sendMessage(tabs[i].id, {user :document.getElementById('usernameTap'),
        pass :document.getElementById('passTap')}, function(response) {
        });
      }
    }); 
    });
}