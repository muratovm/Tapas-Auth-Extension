// chrome.runtime.onMessage.addListener(gotMessage);
console.log('background running');
chrome.browserAction.onClicked.addListener(buttonClicked);
function buttonClicked(tab) {
  alert("in autofill function");

  console.log('entered button clicked');
  console.log(tab);


  let msg = {
    txt: 'lets goooo'
  };
  chrome.tabs.sendMessage(tab.id, msg);
  console.log("in autofill function");

  alert("out autofill function");

}

// let pass;

// fetch('https://web20200225074505.azurewebsites.net/Api/Credential').then(r => r.text()).then(result => {
//     // Result now contains the response text, do what you want...
//     // alert(result);
//     pass = result;
//     alert("Connection Key: " + result);
// })

// alert(response.buttonID);




// fetch('https://web20200225074505.azurewebsites.net/Api/Credential/' + pass + "asd").then(r => r.text()).then(result => {
//   alert("Send messages " + result);
//   console.log("Send messages " + result);
// })