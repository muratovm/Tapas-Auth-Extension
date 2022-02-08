console.log('Chrome extension go?');
chrome.runtime.onMessage.addListener(gotMessage);
function gotMessage(request, sender, sendResponse) {
  setTimeout( () =>  500);

  chrome.storage.sync.get(['curr_username'], function(curr_user) {  
    chrome.storage.sync.get(['curr_password'], function(curr_pass) {  
      document.getElementById('login_field').value=curr_user.curr_username;
      document.getElementById('password').value=curr_pass.curr_password;
    });
  });

//  document.getElementById('login_field').value=request.user;
//   document.getElementById('password').value=request.pass;

// chrome.storage.sync.remove(['curr_username']);
// chrome.storage.sync.remove(['curr_password']);
}

chrome.runtime.onMessage.addListener(gotMessage2);
function gotMessage2(request, sender, sendResponse) {
  setTimeout( () =>  500);
  chrome.storage.sync.get(['curr_username'], function(curr_user) {  
    chrome.storage.sync.get(['curr_password'], function(curr_pass) {  
      document.getElementById('username').value=curr_user.curr_username;
      document.getElementById('password').value=curr_pass.curr_password;
    });
  });

//  document.getElementById('login_field').value=request.user;
//   document.getElementById('password').value=request.pass;
}

chrome.storage.sync.remove(['curr_username']);
chrome.storage.sync.remove(['curr_password']);