//  var secureCb;
//  var secureCbLabel;
var wsUri;
var consoleLog;
var backendRequestLog;
var connectBut;
var disconnectBut;
var routeAction;
var sendMessage;
var sendBut;
var clearLogBut;
var clearbackendRequestLogBut;
var connectionIdInput;
var connectionUrlInput;

var connectionCheckStatusBut;
var connectionSendMessageBut;
var connectionDeleteBut;

function echoHandlePageLoad() {
  //if (window.WebSocket)
  //{
  //  document.getElementById('webSocketSupp').style.display = 'block';
  //}
  //else
  //{
  //  document.getElementById('noWebSocketSupp').style.display = 'block';
  //}

  //    secureCb = document.getElementById('secureCb');
  //    secureCb.checked = false;
  //    secureCb.onclick = toggleTlS;

  //    secureCbLabel = document.getElementById('secureCbLabel')

  wsUri = document.getElementById('wsUri');
  initializeLocation();

  // Connect if the user presses enter in the connect field.
  wsUri.onkeypress = function (e) {
    if (!e) {
      e = window.event;
    }
    var keyCode = e.keyCode || e.which;
    if (keyCode == '13') {
      doConnect();
      return false;
    }
  }

  connectBut = document.getElementById('connect');
  connectBut.onclick = doConnect;

  disconnectBut = document.getElementById('disconnect');
  disconnectBut.onclick = doDisconnect;

  sendMessage = document.getElementById('sendMessage');
  routeAction = document.getElementById('routeAction');
  connectionIdInput = document.getElementById('connectionId');

  // Send message if the user presses enter in the the sendMessage field.
  sendMessage.onkeypress = function (e) {
    if (!e) {
      e = window.event;
    }
    var keyCode = e.keyCode || e.which;
    if (keyCode == '13') {
      doSend();
      return false;
    }
  }

  sendBut = document.getElementById('send');
  sendBut.onclick = doSend;

  consoleLog = document.getElementById('consoleLog');
  backendRequestLog = document.getElementById('backendRequestLog');

  clearLogBut = document.getElementById('clearLogBut');
  clearLogBut.onclick = clearLog;

  clearbackendRequestLogBut = document.getElementById('clearbackendRequestLogBut');
  clearbackendRequestLogBut.onclick = clearbackendRequestLog;

  setGuiConnected(false);

  document.getElementById('disconnect').onclick = doDisconnect;
  document.getElementById('send').onclick = doSend;

  document.getElementById('connectionCheckStatusBut').onclick = connectionCheckStatus;
  document.getElementById('connectionSendMessageBut').onclick = connectionSendMessage;
  document.getElementById('connectionDeleteBut').onclick = connectionDelete;
}

function initializeLocation() {
  // See if the location was passed in.
  wsUri.value = getParameterByName('location');
  if (wsUri.value != '') {
    return;
  }
  var wsScheme = 'ws:';
  if (window.location.protocol.toString() == 'https:') {
    wsScheme = 'wss:';
    //      secureCb.checked = true;
  }
  var wsPort = (window.location.port.toString() == '' ? '' : ':' + window.location.port)
  wsUri.value = wsScheme + '//echo.websocket.org' + wsPort

  //wsUri.value = 'wss://ekn1s6h8vg.execute-api.us-west-2.amazonaws.com/dev'
  //wsUri.value = 'wss://aqgx7fu1o9.execute-api.us-west-2.amazonaws.com/dev'
  wsUri.value = 'wss://aqgx7fu1o9.execute-api.us-west-2.amazonaws.com/dev?token=dsflkn3ewf23'

  connectionUrlInput = document.getElementById('connectionUrl');
  connectionUrlInput.value = 'https://aqgx7fu1o9.execute-api.us-west-2.amazonaws.com/dev/%40connections/'
}

/*  function toggleTlS()
  {
    if (secureCb.checked)
    {
      wsUri.value = wsUri.value.replace('ws:', 'wss:');
    }
    else
    {
      wsUri.value = wsUri.value.replace ('wss:', 'ws:');
    }
  }
*/

function getParameterByName(name, url) {
  if (!url) url = window.location.href;
  name = name.replace(/[\[\]]/g, '\\$&');
  var regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)', 'i'),
    results = regex.exec(url);
  if (!results) return null;
  if (!results[2]) return '';
  return decodeURIComponent(results[2].replace(/\+/g, ' '));
}

function doConnect() {
  if (window.MozWebSocket) {
    logErrorToConsole('Info', 'This browser supports WebSocket using the MozWebSocket constructor');
    window.WebSocket = window.MozWebSocket;
  } else if (!window.WebSocket) {
    logErrorToConsole('ERROR', 'This browser does not have support for WebSocket');
    return;
  }

  // prefer text messages
  var uri = wsUri.value;
  if (uri.indexOf('?') == -1) {
    uri += '?encoding=text';
  } else {
    uri += '&encoding=text';
  }
  //websocket = new WebSocket(uri, ['token']);
  websocket = new WebSocket(uri);
  websocket.onopen = function (evt) {
    onOpen(evt)
  };
  websocket.onclose = function (evt) {
    onClose(evt)
  };
  websocket.onmessage = function (evt) {
    onMessage(evt)
  };
  websocket.onerror = function (evt) {
    onError(evt)
  };
}

function doDisconnect() {
  websocket.close()
}

function doSend() {
  sendMessage.focus();

  var msg = {
    action: routeAction.value,
    message: sendMessage.value
  };

  logTextToConsole('SENT: ' + JSON.stringify(msg));
  websocket.send(JSON.stringify(msg));
}

function logTextToConsole(text) {
  var span = document.createTextNode(text);
  logElementToConsole(consoleLog, span);
}

// label is a string like 'Info' or 'Error'.
function logErrorToConsole(label, text) {
  var span = document.createElement('span');
  span.style.wordWrap = 'break-word';
  span.style.color = 'red';
  span.innerHTML = '<strong>' + label + ':</strong> ';

  var text = document.createTextNode(text);
  span.appendChild(text);

  logElementToConsole(consoleLog, span);
}

function logElementToConsole(logArea, element) {
  if (typeof (element) === 'string') {
    var tempNode = document.createElement('tempNode'); // is a node
    tempNode.innerHTML = element;
    element = tempNode;
  }

  var p = document.createElement('p');
  p.style.wordWrap = 'break-word';
  //    p.innerHTML = getSecureTag();
  p.appendChild(element);

  logArea.appendChild(p);

  while (logArea.childNodes.length > 50) {
    logArea.removeChild(logArea.firstChild);
  }

  logArea.scrollTop = logArea.scrollHeight;
}

function onOpen(evt) {
  logTextToConsole('CONNECTED');
  setGuiConnected(true);

  // For convenience, put the cursor in the message field, and at the end of the text.
  sendMessage.focus();
  sendMessage.selectionStart = sendMessage.selectionEnd = sendMessage.value.length;
}

function onClose(evt) {
  var routeActionInput = document.getElementById('routeAction');
  routeActionInput.value = 'register';

  logTextToConsole('DISCONNECTED');
  setGuiConnected(false);
}

function onMessage(evt) {
  var span = document.createElement('span');
  span.style.wordWrap = 'break-word';
  span.style.color = 'blue';
  span.innerHTML = 'RECEIVED: ';

  var message = document.createTextNode(evt.data);
  span.appendChild(message);

  var routeActionInput = document.getElementById('routeAction');
  // && connectionIdInput.value === ''
  if (routeActionInput.value === 'register') {
    routeActionInput.value = 'onMessage'
    connectionIdInput.value = message.textContent;
  }

  logElementToConsole(consoleLog, span);
}

function onError(evt) {
  logErrorToConsole('ERROR', evt.data);
}

function setGuiConnected(isConnected) {
  wsUri.disabled = isConnected;
  connectBut.disabled = isConnected;
  disconnectBut.disabled = !isConnected;
  sendMessage.disabled = !isConnected;
  sendBut.disabled = !isConnected;
  //    secureCb.disabled = isConnected;
  var labelColor = 'black';
  if (isConnected) {
    labelColor = '#999999';
  }
  //    secureCbLabel.style.color = labelColor;

}

function clearLog() {
  while (consoleLog.childNodes.length > 0) {
    consoleLog.removeChild(consoleLog.lastChild);
  }
}

function clearbackendRequestLog() {
  while (backendRequestLog.childNodes.length > 0) {
    backendRequestLog.removeChild(backendRequestLog.lastChild);
  }
}

function connectionCheckStatus() {
  if (connectionIdInput.value === '') {
    logElementToConsole(backendRequestLog, 'Connection ID cannot be empty.');
    return;
  }

  var cUrl = connectionUrlInput.value;
  var splitArray = cUrl.split(".");
  var regionName = splitArray[2];
  var serviceName = splitArray[1];

  jQuery.ajax({
    url: "/awsbackend/GetStatus/" + encodeURIComponent(connectionIdInput.value), //請求的url地址
    contentType: "application/json",
    dataType: "json", //返回格式為json
    async: true, //請求是否非同步，預設為非同步，這也是ajax重要特性
    data: JSON.stringify({
      "connectionUrl": cUrl,
      "regionName": regionName,
      "serviceName": serviceName
    }), //引數值
    type: "POST", //請求方式
    beforeSend: function () {
      //請求前的處理
    },
    success: function (jsonResult) {
      //請求成功時處理
      console.log(jsonResult);

      if (jsonResult.StatusCode === "200 OK") {
        logElementToConsole(backendRequestLog, 'Check Status Result: ' + JSON.stringify(jsonResult));
      }
    },
    complete: function () {
      //請求完成的處理
    },
    error: function (err) {
      //請求出錯處理
      console.log(err);
    }
  });
}

function connectionSendMessage() {
  if (connectionIdInput.value === '') {
    logElementToConsole(backendRequestLog, 'Connection ID cannot be empty.');
    return;
  }

  var cUrl = connectionUrlInput.value;
  var splitArray = cUrl.split(".");
  var regionName = splitArray[2];
  var serviceName = splitArray[1];
  var sendMessageToConnection = document.getElementById('sendMessageToConnection');

  jQuery.ajax({
    url: "/awsbackend/SendMessage/" + encodeURIComponent(connectionIdInput.value), //請求的url地址
    contentType: "application/json",
    dataType: "json", //返回格式為json
    async: true, //請求是否非同步，預設為非同步，這也是ajax重要特性
    data: JSON.stringify({
      "connectionUrl": cUrl,
      "regionName": regionName,
      "serviceName": serviceName,
      "message": sendMessageToConnection.value
    }), //引數值
    type: "POST", //請求方式
    beforeSend: function () {
      //請求前的處理
    },
    success: function (jsonResult) {
      //請求成功時處理
      console.log(jsonResult);

      if (jsonResult.StatusCode === "200 OK") {
        logElementToConsole(backendRequestLog, 'Send Message Result: ' + JSON.stringify(jsonResult));
      }
    },
    complete: function () {
      //請求完成的處理
    },
    error: function (err) {
      //請求出錯處理
      console.log(err);
    }
  });
}

function connectionDelete() {
  if (connectionIdInput.value === '') {
    logElementToConsole(backendRequestLog, 'Connection ID cannot be empty.');
    return;
  }

  var cUrl = connectionUrlInput.value;
  var splitArray = cUrl.split(".");
  var regionName = splitArray[2];
  var serviceName = splitArray[1];

  jQuery.ajax({
    url: "/awsbackend/DeleteConnection/" + encodeURIComponent(connectionIdInput.value), //請求的url地址
    contentType: "application/json",
    dataType: "json", //返回格式為json
    async: true, //請求是否非同步，預設為非同步，這也是ajax重要特性
    data: JSON.stringify({
      "connectionUrl": cUrl,
      "regionName": regionName,
      "serviceName": serviceName
    }), //引數值
    type: "POST", //請求方式
    beforeSend: function () {
      //請求前的處理
    },
    success: function (jsonResult) {
      //請求成功時處理
      console.log(jsonResult);

      if (jsonResult.StatusCode === "204 No Content") {
        logElementToConsole(backendRequestLog, 'Disconnection Result: ' + JSON.stringify(jsonResult));
      }
    },
    complete: function () {
      //請求完成的處理
    },
    error: function (err) {
      //請求出錯處理
      console.log(err);
    }
  });
}



/*  function getSecureTag()
  {
    if (secureCb.checked)
    {
      return '<img src="img/tls-lock.png" width="6px" height="9px"> ';
    }
    else
    {
      return '';
    }
  }
*/

window.addEventListener('load', echoHandlePageLoad, false);