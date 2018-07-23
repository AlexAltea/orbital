/* Global */
var context = {
    // Confirm whether the user actually wants to initiate the dump
    safety: false,

    // Socket for the WebSockets server
    socket: undefined,
};

/* Logging */
function log(message, level) {
    level = (typeof level !== 'undefined') ? level : 'log';
    // Escape message
    var message = message.toString()
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
    // Print message
    var logs = document.getElementById('logs-internal');
    switch (level) {
    case 'log':
        var color = '#fff'; break;
    case 'warn':
        var color = '#ff0'; break;
    case 'error': 
        var color = '#f00'; break;
    default:
        var color = '#fff'; break;
    }
    logs.innerHTML += `<span style='color:${color}'>${message}</span><br>`;
}

if (typeof console != 'undefined') {
    var levels = ['log', 'warn', 'error'];
    levels.forEach(function (level) {
        var original = '_' + level;        
        if (typeof console[level] != 'undefined') {
            console[original] = console[level];
        } else {
            console[original] = function () {};
        }            
    });
}

console.log   = ((msg) => { console._log(msg);   log(msg, 'log'); });
console.warn  = ((msg) => { console._warn(msg);  log(msg, 'warn'); });
console.error = ((msg) => { console._error(msg); log(msg, 'error'); });

/* WebSockets */
function ws_init() {
    // Handlers
    var enable_ws = function () {
        transfer_mode("ws");
        var info_ws = document.getElementById(`info-ws`);
        info_ws.innerHTML = `Detected: <i>${context.socket.url}</i>`;
    }
    var disable_ws = function () {
        transfer_mode("usb");
        var button_ws = document.getElementById(`output-ws`);
        button_ws.classList.add("disabled");
    }
    // Connect to server
    try {
        context.socket = new WebSocket(`ws://${window.location.host}/ws`);
    } catch (e) {
        disable_ws();
    }
    context.socket.onopen = enable_ws;
    context.socket.onerror = disable_ws;
    context.socket.binaryType = "arraybuffer";
}

/* Tranfer */
function transfer_mode(mode) {
    context.transfer_mode = mode;
    var button_usb = document.getElementById(`output-usb`);
    var button_ws = document.getElementById(`output-ws`);
    if (mode == 'ws' && !button_ws.classList.contains('disabled')) {
        button_ws.classList.add("active");
        button_usb.classList.remove("active");
    }
    if (mode == 'usb' && !button_usb.classList.contains('disabled')) {
        button_usb.classList.add("active");
        button_ws.classList.remove("active");
    }
}

function transfer_blob(name, data) {
    if (context.transfer_mode == 'ws') {
        context.socket.send(name);
        context.socket.send(data);
    }
    if (context.transfer_mode == 'usb') {
        throw 'Unimplemented';
    }
}

/* Dumper */
function start() {
    /* Ask the user for confirmation */
    if (context.safety) {
        var msg = '';
        msg += 'Are you sure you want to dump your system files?\n';
        msg += 'This process could take few minutes.';
        if (!confirm(msg)) {
            return;
        }
    }
    /* Load and execute exploit */
    var script = document.createElement('script');
    script.onload = function () {
        exploit();
    };
    script.src = context.base + 'exploit.js';
    document.body.appendChild(script);
    /* Update interface */
    document.onclick = undefined;
}

function main() {
    ws_init();
    var found = navigator.userAgent.match(/PlayStation 4 ([0-9]+\.[0-9]+)/);
    if (found) {
        var version = found[1];
        console.log(`Detected PlayStation 4 on version ${version}`);
        switch (version) {
        case '4.55':
            context.base = 'exploit/455/';
            break;
        case '5.00':
            context.base = 'exploit/500/';
            break;
        case '5.01':
            context.base = 'exploit/500/';
            break;
        default:
            alert("This PlayStation 4 sofware version is not supported");
        }
    } else {
        console.error("Run this on the target PlayStation 4 machine");
    }
}

document.addEventListener("DOMContentLoaded", main);
