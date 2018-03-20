/* Global */
var context = {
    safety: false,
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
    var found = navigator.userAgent.match(/PlayStation 4 ([0-9]+\.[0-9]+)/);
    if (found) {
        var version = found[1];
        console.log(`Detected PlayStation 4 on version ${version}`);
        switch (version) {
        case '4.55':
            context.base = 'private/455/';
            document.onclick = start;
            break;
        case '5.00':
            context.base = 'private/500/';
            document.onclick = start;
            break;
        case '5.01':
            context.base = 'private/500/';
            document.onclick = start;
            break;
        default:
            alert("This PlayStation 4 sofware version is not supported");
        }
    } else {
        alert("Run this on the target PlayStation 4 machine");
    }
}

document.addEventListener("DOMContentLoaded", main);
