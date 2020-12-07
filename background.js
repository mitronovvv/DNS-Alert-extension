/* global chrome */
const EXCLUSIONS = [ 'google', 'gstatic' ];

const options = {
    doubleCheck: true, 
    doubleCheckType: 'dig', 
    doubleCheckUrl: 'https://api.dig.zone/v1/' 
};

const MAIN_REGEX = /^(?:(\w+):)?\/\/([^/?#]+)/;
const DIG_REGEX = /;; ANSWER SECTION:((\n[a-z.A-Z]+.\s\d+\sIN\sA\s\d+.\d+.\d+.\d+)+)/;
const DIG_IP_REGEX = /[a-z.A-Z]+.\s\d+\sIN\sA\s(\d+.\d+.\d+.\d+)/;

let hosts = {};
chrome.storage.local.get('DNSAlertHosts', function(data){
    hosts = data.DNSAlertHosts || {}; 
});

const notifications = {};

chrome.notifications.onClosed.addListener(function(notificationId){
    delete notifications[notificationId];
});
chrome.notifications.onButtonClicked.addListener(function(notificationId, buttonIndex){
    switch(buttonIndex){
    case 0:
        addIPs(notifications[notificationId].host, [notifications[notificationId].ip]);
        break;
    case 1:
        chrome.tabs.create({ url: 'https://en.wikipedia.org/wiki/DNS_spoofing'});
        break;
    }
    delete notifications[notificationId];
});

function debug() {
    //console.log.apply(console, arguments);
}

function addIPs(url, ips){
    if(!hosts[url]) hosts[url] = [];
    for(const ip of ips){
        if(!hosts[url].includes(ip)) hosts[url].push(ip); 
    }
    chrome.storage.local.set({ 'DNSAlertHosts': hosts }); 
}

function checkURL(host, details){
    debug(host, 'resolved to', details.ip);
    for(const e of EXCLUSIONS) {
        if(host.indexOf(e) !== -1) return updateIcon(details.tabId, 'neutral.png');
    }
    if(hosts[host] && hosts[host].includes(details.ip)) updateIcon(details.tabId, 'good.png');
    else if(!Array.isArray(hosts[host]) || hosts[host].length === 0){
        if(options.doubleCheck) { 
            switch(options.doubleCheckType){
            case 'dig':
                fetch(`${options.doubleCheckUrl}${host}`)
                    .then(function(response){
                        response.text().then(function(result){
                            debug('dig result', result);
                            const match = DIG_REGEX.exec(result); 
                            const ips = []; 
                            debug('dig match', match);
                            if(match && match[1]) {
                                const split = match[1].split('\n'); 
                                for(let i=1; i<split.length;i++){
                                    const m2 = DIG_IP_REGEX.exec(split[i]);
                                    debug('found ip', m2);
                                    if(m2 && m2[1]) ips.push(m2[1]);
                                }
                            }
                            if(!ips.includes(details.ip)) ips.push(details.ip);
                            debug('adding ips', ips);
                            addIPs(host, ips);
                        });
                    });
            }
        } else { 
            addIPs(host, [details.ip]);
        }
        updateIcon(details.tabId, 'neutral.png');
    }
    else { 
        for(const notificationId in notifications) {
            
            if(notifications[notificationId].host === host && notifications[notificationId].ip === details.ip) return;
        }
        chrome.notifications.create('', {
            title: 'This site IP address has changed',
            message: `${host} usually had the following IPs: ${hosts[host]} but now resolved to ${details.ip}. This might be a DNS attack.`,
            type: 'basic',
            iconUrl: 'bad.png',
            buttons: [
                {title: 'Add this IP'},
                {title: 'Learn more'}
            ],
            silent: true
        }, function(notificationId){
            notifications[notificationId] = {
                host,
                ip: details.ip
            };
        });
        updateIcon(details.tabId, 'bad.png');
    }
}

function updateIcon(tabId, image){
    chrome.browserAction.setIcon({ 
        path: image,
        tabId : tabId
    });
}

chrome.webRequest.onCompleted.addListener(function (details) {
    const match = MAIN_REGEX.exec(details.url); 
    if(!match || !match[1] || !match[2]) return; 
    if(!(match[1] === 'http' || match[1] === 'https')) return; 
    checkURL(match[2].toLowerCase(), details);
}, {
    urls : ['<all_urls>']
},
[]);
