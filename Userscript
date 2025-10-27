// ==UserScript==
// @name         BrowserGuard
// @namespace    https://github.com/jhorner6511
// @author       Johnathon M. Horner
// @version      0.0.1
// @description  In-browser antivirus for enhanced web security.
// @match        *://*/*
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_addStyle
// @grant        GM_registerMenuCommand
// @grant        GM_xmlhttpRequest
// @require      https://kjur.github.io/jsrsasign/jsrsasign-all-min.js
// @run-at       document-start
// @license      MIT
// ==/UserScript==

(function() {
    'use strict';

    // --- Configuration ---
    const DEFINITIONS_URL = 'https://example.com/virus_definitions.json';
    const PUBLIC_KEY_URL = 'https://example.com/public_key.pem'; // URL for public key
    const PUBLIC_KEY_FINGERPRINT = 'YOUR_PUBLIC_KEY_FINGERPRINT'; // Hardcoded fingerprint
    const DEFINITIONS_KEY = 'virusDefinitions';
    const DEFINITIONS_VERSION_KEY = 'definitionsVersion';
    const LAST_UPDATE_KEY = 'lastUpdate';
    const UPDATE_INTERVAL = 7 * 24 * 60 * 60 * 1000;
    const WHITELIST_KEY = 'whitelist';
    const LOG_KEY = 'avLog';
    const API_KEY_KEY = 'apiKey';

    let apiKey = GM_getValue(API_KEY_KEY, '');
    let paused = false;
    let log = [];

    const scannedElementsCache = new Map(); //Cache for scanned elements
    let whitelist = GM_getValue(WHITELIST_KEY, []).map(item => ({url:item.url, notes: item.notes})); // Load whitelist with notes

    let currentDefinitions = [];
    let regexCache = {};  // Precompiled regex patterns

    let scanningEnabled = {
        json: GM_getValue('scanJson', false),
        xhr: GM_getValue('scanXhr', true),
        iframe: GM_getValue('scanIframe', false)
    };

    // --- UI Elements ---
    let dashboard = null;
    let threatCounts = {
        blocked: 0,
        detected: 0,
        ignored: 0
    };
    let updateStatus = "Idle";
    let dashboardColor = "rgba(0, 0, 0, 0.8)";
    let lastUpdatedTimestamp = GM_getValue(LAST_UPDATE_KEY, 'Never');
    let autoBlockHighRisk = GM_getValue('autoBlock', true);

    // --- Logging Function ---
    let logSaveTimer = null;
    function saveLog() {
        GM_setValue(LOG_KEY, JSON.stringify(log));
        logSaveTimer = null;
    }

    function logMessage(level, message) {
        const timestamp = new Date().toISOString();
        const logEntry = `[${timestamp}] ${level.toUpperCase()}: ${message.substring(0,250)}`;//Limit log entry size
        console[level](logEntry); // Native console logging
        log.push({ timestamp, level, message });

        if (log.length > 100) log.shift();

        if (logSaveTimer) {
            clearTimeout(logSaveTimer);
        }
        logSaveTimer = setTimeout(saveLog, 2000);
    }

    // Load stored log on startup
    try {
        const storedLog = GM_getValue(LOG_KEY, '[]');
        log = JSON.parse(storedLog);
    } catch (error) {
        console.error("Error parsing stored log:", error);
        log = [];
    }

      // --- Utility function for SHA-256 hashing (ASYNC) ---
    async function sha256_async(str) {
        const buffer = new TextEncoder().encode(str);
        const digest = await crypto.subtle.digest('SHA-256', buffer);
        return Array.from(new Uint8Array(digest))
            .map(x => x.toString(16).padStart(2, '0'))
            .join('');
    }

    // --- Utility function for SHA-256 hashing (SYNC) ---
    function sha256_sync(str) {
        // Use the jsrsasign library you already have
        try {
            const md = new KJUR.crypto.MessageDigest({"alg": "sha256", "prov": "cryptojs"});
            return md.digest(str);
        } catch (e) {
            logMessage('error', `Sync SHA256 failed: ${e}`);
            return null; // Handle hash failure
        }
    }

    // --- Asymmetric Signature Verification ---
    async function verifySignature(data, signature, publicKey) {
        try {
            const isValid = KJUR.crypto.ECDSA.verify(data, signature, publicKey, 'SHA256');
            return isValid;
        } catch (error) {
            logMessage('error', `Signature verification error: ${error}`);
            return false;
        }
    }

    async function downloadAndVerifyDefinitions() {
        try {
            // 1. Fetch Public Key and Definitions Concurrently
            const [publicKeyResponse, definitionsResponse] = await Promise.all([
                new Promise((resolve, reject) => {
                    GM_xmlhttpRequest({
                        method: 'GET',
                        url: PUBLIC_KEY_URL,
                        onload: resolve,
                        onerror: reject,
                        responseType: 'text' // Expect plain text
                    });
                }),
                new Promise((resolve, reject) => {
                    GM_xmlhttpRequest({
                        method: 'GET',
                        url: DEFINITIONS_URL,
                        onload: resolve,
                        onerror: reject,
                        responseType: 'json' // Expect JSON data
                    });
                })
            ]);

            if (publicKeyResponse.status !== 200) {
                throw new Error(`Failed to fetch public key: Status ${publicKeyResponse.status}`);
            }

            if (definitionsResponse.status !== 200) {
                throw new Error(`Failed to fetch definitions: Status ${definitionsResponse.status}`);
            }

            const publicKey = publicKeyResponse.responseText; // Public key as text
            const downloadedDefinitions = definitionsResponse.response; // Parsed JSON

            // 2. Validate Public Key Fingerprint
            if (PUBLIC_KEY_FINGERPRINT && publicKey) {
                // Calculate fingerprint (SHA-256 hash) of the public key
                // CHANGE THIS:
                // const keyHash = sha256_sync(publicKey);
                // TO THIS:
                const keyHash = await sha256_async(publicKey); // Use the non-blocking version here

                // Compare calculated hash with the trusted fingerprint
                if (keyHash !== PUBLIC_KEY_FINGERPRINT) {
                    throw new Error('Public key fingerprint does not match!');
                }
            } else {
                logMessage("warn", 'Public Key Fingerprint is not defined!');
            }

            // 3. Version Check
            const currentVersion = GM_getValue(DEFINITIONS_VERSION_KEY, null);
            if (downloadedDefinitions.version === currentVersion) {
                logMessage("info", "Definitions are already up to date.");
                updateStatus = "Up-to-date";
                dashboardColor = "rgba(0, 0, 0, 0.8)"; // Back to normal
                updateDashboard();
                return;
            }

            // 4. Verify Signature (covers the entire payload)
            const data = JSON.stringify(downloadedDefinitions.data);
            const signature = downloadedDefinitions.signature;

            const isValidSignature = await verifySignature(data, signature, publicKey);

            if (!isValidSignature) {
                logMessage("error", "Signature verification failed!");
                updateStatus = "Signature Failed!";
                dashboardColor = "rgba(255, 0, 0, 0.8)"; // Red for error
                updateDashboard();
                return;
            }

            // 5. Precompile Regex Patterns
            const newRegexCache = {}; // Temporary cache
            downloadedDefinitions.data.definitions.forEach(definition => {
                try {
                    newRegexCache[definition.pattern] = new RegExp(definition.pattern, 'i');
                } catch (error) {
                    logMessage("error", `Error precompiling regex pattern ${definition.pattern}: ${error}`);
                }
            });

            // If ALL checks pass, update definitions atomically
            GM_setValue(DEFINITIONS_KEY, downloadedDefinitions.data);
            GM_setValue(DEFINITIONS_VERSION_KEY, downloadedDefinitions.version);
            GM_setValue(LAST_UPDATE_KEY, Date.now());

            // Update Global Variables
            const definitionsData = GM_getValue(DEFINITIONS_KEY, { definitions: [] });
            currentDefinitions = definitionsData.definitions || []; // <--- LOAD INTO MEMORY
            regexCache = {}; // Clear old cache
            currentDefinitions.forEach(definition => {
                try {
                    regexCache[definition.pattern] = new RegExp(definition.pattern, 'i');
                } catch (e) { /* ... */ }
            });
            lastUpdatedTimestamp = new Date().toLocaleString();

            logMessage("info", `Definitions updated to version ${downloadedDefinitions.version}`);
            updateStatus = "Updated!";
            dashboardColor = "rgba(0, 128, 0, 0.8)"; // Green for success
            updateDashboard();

        } catch (error) {
            logMessage("error", `Definition update failed: ${error}`);
            updateStatus = "Update Failed!";
            dashboardColor = "rgba(255, 0, 0, 0.8)"; // Red for error
            updateDashboard();
        }
    }

    async function updateDefinitions() {
        updateStatus = "Updating...";
        dashboardColor = "rgba(255, 255, 0, 0.8)"; // Yellow for updating
        updateDashboard();

        logMessage("info", "Checking for definition updates...");
        await downloadAndVerifyDefinitions();

        updateDashboard();
    }

    // --- Scanning Function ---
    function scanContent(contentType, content, url = null) {
        if (paused || (url && isWhitelisted(url))) {
            return;
        }

        // Improve Cache for Inline Scripts (Hash the content)
        let cacheKey = url;
        if (contentType === "script" && content) {
            cacheKey = sha256_sync(content);
        }

        if (cacheKey && scannedElementsCache.has(cacheKey)) {
            return;
        }

        // The definitions are already in memory!
        if (!currentDefinitions) {
            return;
        }

        let threatFound = false;
        for (const definition of currentDefinitions) { // <--- USE THE GLOBAL
            // Use precompiled regex pattern
            const regex = regexCache[definition.pattern];
            if (!regex) {
                logMessage("error", `Regex pattern not found in cache: ${definition.pattern}`);
                continue;
            }

            if (regex.test(content)) {
                logMessage("warn", `Potential threat detected: ${definition.description}, Risk: ${definition.risk}`);

                threatFound = true;

                // Take action based on risk level
                switch (definition.risk) {
                    case 'high':
                        threatCounts.detected++;
                        if (autoBlockHighRisk) {
                            //Quarantine instead of removing the script
                            logMessage("warn", "High risk threat, quarantining script");
                            if (contentType === "script") {
                                //Quarantine Script content and URL to prevent future executions
                                const scriptTag = document.querySelector(`script[src="${url}"]`);
                                if (scriptTag) {
                                    scriptTag.dataset.avQuarantined = true;
                                    scriptTag.style.display = 'none'; // Hide it.
                                }
                            }
                            threatCounts.blocked++;
                        } else {
                            threatCounts.ignored++;
                            if (confirm(`High-risk script detected. Block it?`)) {
                                //if user allows remove the script
                                if (contentType === "script") {
                                    //Quarantine Script content and URL to prevent future executions
                                    const scriptTag = document.querySelector(`script[src="${url}"]`);
                                    if (scriptTag) {
                                        scriptTag.dataset.avQuarantined = true;
                                        scriptTag.style.display = 'none'; // Hide it.
                                    }
                                }
                                threatCounts.blocked++;
                            }

                        }
                        break;
                    case 'medium':
                        logMessage("warn", "Medium risk threat");
                        threatCounts.detected++;
                        break;
                    case 'low':
                        logMessage("warn", "Low risk threat");
                        threatCounts.detected++;
                        break;
                    default:
                        logMessage("warn", "Suspicious activity");
                        break;
                }

                updateDashboard();

                if (cacheKey) {
                    scannedElementsCache.set(cacheKey, true);
                }
            }
        }
        return threatFound;
    }

    // --- DOM Mutation Observer ---
    const nativeAppendChild = Node.prototype.appendChild;

    Node.prototype.appendChild = function(newNode) {
        if (newNode && newNode.tagName === 'SCRIPT' && !paused) { // Added !paused check
            let content = newNode.src ? newNode.src : newNode.textContent;

            // Run the scan synchronously
            const isThreat = scanContent('script', content, newNode.src);

            if (isThreat && autoBlockHighRisk) {
                logMessage('warn', `BLOCKING script: ${newNode.src || 'inline script'}`);
                threatCounts.blocked++;
                updateDashboard();
                // Don't append it! Just return the node.
                return newNode;
            }
        }
        // If it's not a script or it's clean, append it normally
        return nativeAppendChild.call(this, newNode);
    };

    const observer = new MutationObserver(function(mutations) {
        if (paused) {
            return;
        }

        mutations.forEach(function(mutation) {
            if (mutation.addedNodes) {
                mutation.addedNodes.forEach(function(node) {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        // Scan inline event handlers
                        if (node.hasAttributes()) {
                            const attributes = node.attributes;
                            for (let i = 0; i < attributes.length; i++) {
                                const attribute = attributes[i];
                                if (attribute.name.startsWith('on')) {
                                    scanContent('event', attribute.value);
                                }
                            }
                        }
                         if (node.tagName === 'IFRAME') {
                            if (node.src) {
                                // Handle cross-origin iframes: check if accessible
                                GM_xmlhttpRequest({
                                    method: 'GET',
                                    url: node.src,
                                    onload: function(response) {
                                        try{
                                            if (response.status === 200) {
                                                scanContent('iframe', response.responseText, node.src);
                                            }
                                        } catch (error) {
                                             logMessage('warn', `Cannot scan content of cross-origin iframe ${node.src}`);
                                        }

                                    },
                                    onerror: function(error) {
                                        logMessage("warn", `Cannot scan content of cross-origin iframe ${node.src}`);
                                    }
                                });
                            }

                        } else if (node.tagName === 'LINK' && node.rel === 'stylesheet') {
                            // Scan external CSS files
                            GM_xmlhttpRequest({
                                method: 'GET',
                                url: node.href,
                                onload: function(response) {
                                    try{
                                        if (response.status === 200) {
                                            scanContent('css', response.responseText, node.href);
                                        }
                                    } catch (error) {
                                         logMessage('error', `XHR responseText failed: ${error}`);
                                    }
                                },
                                onerror: function(error){
                                    logMessage("error", `Error fetching ${node.href}: ${error}`);
                                }
                            });
                        }
                    }
                });
            }
        });

    });

    // --- Scanning eval() calls ---
    function scanEvalCalls(code) {
        //Simple pattern but can be improved
        const evalRegex = /eval\((.*?)\)/g;
        let match;
        while ((match = evalRegex.exec(code)) !== null) {
            scanContent('eval', match[1]);
        }
    }

    // --- Function to scan JSON responses ---
    function scanJsonResponse(response, url) {
        if (scanningEnabled.json) {
            scanContent('json', JSON.stringify(response),url);
        }
    }

    // --- Initialize ---
    async function initialize() {
        // Check if definitions need updating
        await downloadAndVerifyDefinitions();

        // --- Override XMLHttpRequest and Fetch API to scan responses ---
         const originalOpen = XMLHttpRequest.prototype.open;
         XMLHttpRequest.prototype.open = function (method, url) {
            this.addEventListener('load', function () {
                let contentType;
                try{
                    contentType = this.getResponseHeader('Content-Type');
                    if (contentType) {
                       if (contentType.includes('application/json') && scanningEnabled.json) {
                           try {
                               const jsonResponse = JSON.parse(this.responseText);
                               scanJsonResponse(jsonResponse, url);
                           } catch (error) {
                                logMessage('error', `Error parsing JSON response from ${url}: ${error}`);
                           }
                        }
                        // --- THIS IS THE FIX ---
                        else if (contentType.includes('javascript') || contentType.includes('text/plain')) {
                           try {
                                const textResponse = this.responseText;
                                // Scan this as a script!
                                scanContent('script', textResponse, url);
                            } catch (error) {
                                 logMessage('error', `Error parsing responseText from ${url}: ${error}`);
                            }
                        }
                    }
                 } catch (error) {
                      logMessage('error', `getResponseHeader failed: ${error}`);
                 }
            });
            originalOpen.apply(this, arguments);
         };

         // Fetch API
        const originalFetch = window.fetch;
        window.fetch = async function(url, options) {
            try{
                const response = await originalFetch(url, options);
                const contentType = response.headers.get('Content-Type');

                if (contentType) {
                    if (contentType.includes('application/json') && scanningEnabled.json) {
                        try {
                            const jsonResponse = await response.clone().json();
                            scanJsonResponse(jsonResponse, url);
                        } catch (error) {
                            logMessage('error', `Error parsing JSON response from ${url}: ${error}`);
                        }
                    }
                    // --- THIS IS THE FIX ---
                    else if (contentType.includes('javascript') || contentType.includes('text/plain')) {
                        try {
                            const textResponse = await response.clone().text();
                            // Scan this as a script!
                            scanContent('script', textResponse, url);
                        } catch (error) {
                             logMessage('error', `Error cloning response text from ${url}: ${error}`);
                        }
                    }
                }
                  return response;
             } catch (error) {
                  logMessage('error', `Original Fetch failed from ${url}: ${error}`);
             }
        };

        //Add logic to scan eval calls
        scanEvalCalls(document.body.innerHTML);

        observer.observe(document.documentElement, {
            childList: true,
            subtree: true,
            attributes: true // Observe attribute changes for inline event handlers
        });

        createDashboard();
    }

    // --- Whitelist Management ---
    function addToWhitelist(url, notes = "") {
        if (!isWhitelisted(url)) {
            whitelist.push({ url: url, notes: notes });
            GM_setValue(WHITELIST_KEY, JSON.stringify(whitelist));
            logMessage("info", `Added ${url} to whitelist`);
        }
    }

    function removeFromWhitelist(url) {
        whitelist = whitelist.filter(item => item.url !== url);
        GM_setValue(WHITELIST_KEY, JSON.stringify(whitelist));
        logMessage("info", `Removed ${url} from whitelist`);
    }

    function isWhitelisted(url) {
        return whitelist.some(item => item.url === url);
    }

    //Validate URL before adding
    function isValidUrl(url) {
        try {
            new URL(url);
            return true;
        } catch (error) {
            return false;
        }
    }

    // --- Visual Dashboard ---
    function createDashboard() {
         const dashboardCSS = `
            #avDashboard {
                position: fixed;
                top: 10px;
                left: 10px;
                background: ${dashboardColor};
                color: white;
                padding: 10px;
                z-index: 10000;
                font-family: sans-serif;
                border-radius: 5px;
            }
            #avDashboard button {
                background-color: #555;
                color: white;
                border: none;
                padding: 5px 10px;
                cursor: pointer;
                border-radius: 3px;
                margin-right: 5px;
            }
            #avDashboard input[type="checkbox"] {
                margin-right: 5px;
            }
         `;

        dashboard = document.createElement('div');
        dashboard.id = 'avDashboard';
        document.body.appendChild(dashboard);

        dashboard.innerHTML = `
            <h3>In-Browser Antivirus</h3>
            <p>Status: <span id="avStatus">${updateStatus}</span></p>
            <p>Blocked: <span id="avBlocked">${threatCounts.blocked}</span> | Detected: <span id="avDetected">${threatCounts.detected}</span> | Ignored: <span id="avIgnored">${threatCounts.ignored}</span></p>
            <p>Last Updated: <span id="avLastUpdated">${lastUpdatedTimestamp}</span></p>
            <button id="avUpdateBtn">Update Definitions</button>
            <button id="avPauseBtn">${paused ? 'Resume Protection' : 'Pause Protection'}</button>
            <button id="avWhitelistBtn">Manage Whitelist</button>
            <div>
                <input type="checkbox" id="avAutoBlockCheckbox" ${autoBlockHighRisk ? 'checked' : ''}>
                <label for="avAutoBlockCheckbox">Auto-block High Risk</label>
            </div>
            <div>
                <input type="checkbox" id="avJsonScanCheckbox" ${scanningEnabled.json ? 'checked' : ''}>
                <label for="avJsonScanCheckbox">Scan JSON</label>

                <input type="checkbox" id="avXhrScanCheckbox" ${scanningEnabled.xhr ? 'checked' : ''}>
                <label for="avXhrScanCheckbox">Scan XHR/Fetch</label>

                <input type="checkbox" id="avIframeScanCheckbox" ${scanningEnabled.iframe ? 'checked' : ''}>
                <label for="avIframeScanCheckbox">Scan Iframes</label>
            </div>
        `;

        GM_addStyle(dashboardCSS);

        document.getElementById('avUpdateBtn').addEventListener('click', updateDefinitions);
        document.getElementById('avPauseBtn').addEventListener('click', togglePause);
        document.getElementById('avWhitelistBtn').addEventListener('click', showWhitelistDialog);

        // Auto-block toggle
        const autoBlockCheckbox = document.getElementById('avAutoBlockCheckbox');
        autoBlockCheckbox.addEventListener('change', function() {
            autoBlockHighRisk = this.checked;
            GM_setValue('autoBlock', autoBlockHighRisk);
        });

        // Toggle scanning options
        const jsonScanCheckbox = document.getElementById('avJsonScanCheckbox');
        jsonScanCheckbox.addEventListener('change', function() {
            scanningEnabled.json = this.checked;
            GM_setValue('scanJson', scanningEnabled.json);
        });

        const xhrScanCheckbox = document.getElementById('avXhrScanCheckbox');
        xhrScanCheckbox.addEventListener('change', function() {
            scanningEnabled.xhr = this.checked;
            GM_setValue('scanXhr', scanningEnabled.xhr);
        });

        const iframeScanCheckbox = document.getElementById('avIframeScanCheckbox');
        iframeScanCheckbox.addEventListener('change', function() {
            scanningEnabled.iframe = this.checked;
            GM_setValue('scanIframe', scanningEnabled.iframe);
        });

        updateDashboard();
    }

    function updateDashboard() {
        if (!dashboard) return;
        dashboard.style.background = dashboardColor;
        document.getElementById('avStatus').textContent = updateStatus;
        document.getElementById('avBlocked').textContent = threatCounts.blocked;
        document.getElementById('avDetected').textContent = threatCounts.detected;
        document.getElementById('avIgnored').textContent = threatCounts.ignored;
        document.getElementById('avLastUpdated').textContent = lastUpdatedTimestamp;
    }

    function togglePause() {
        paused = !paused;
        updateDashboard();
    }

    // --- Whitelist Dialog ---
    function showWhitelistDialog() {
        const dialogCSS = `
            #avWhitelistDialog {
                position: fixed;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                background: rgba(0, 0, 0, 0.9);
                color: white;
                padding: 20px;
                z-index: 10001;
                font-family: sans-serif;
                border-radius: 5px;
            }
            #avWhitelistDialog ul {
                list-style-type: none;
                padding: 0;
            }
            #avWhitelistDialog li {
                margin-bottom: 5px;
            }
            .avRemoveWhitelistBtn {
                margin-left: 10px;
                background-color: #444;
                color: white;
                border: none;
                padding: 5px 10px;
                cursor: pointer;
                border-radius: 3px;
            }
        `;
        const dialog = document.createElement('div');
        dialog.id = 'avWhitelistDialog';
        document.body.appendChild(dialog);

        let whitelistItems = whitelist.map(item => `
                <li>
                    ${item.url} - ${item.notes || "No notes"}
                    <button class="avRemoveWhitelistBtn" data-url="${item.url}">Remove</button>
                </li>
            `).join('');

        dialog.innerHTML = `
            <h3>Whitelist Management</h3>
            <ul>
                ${whitelistItems}
            </ul>
            <input type="text" id="avNewWhitelistUrl" placeholder="Enter URL to whitelist">
            <input type="text" id="avNewWhitelistNotes" placeholder="Enter notes for this URL">
            <button id="avAddWhitelistBtn">Add URL</button>
            <button id="avExportWhitelistBtn">Export Whitelist</button>
            <button id="avImportWhitelistBtn">Import Whitelist</button>
            <button id="avCloseWhitelistBtn">Close</button>
        `;
        GM_addStyle(dialogCSS);

        document.getElementById('avAddWhitelistBtn').addEventListener('click', function() {
            const url = document.getElementById('avNewWhitelistUrl').value;
            const notes = document.getElementById('avNewWhitelistNotes').value;

            if (isValidUrl(url)) {
                addToWhitelist(url, notes);
                document.getElementById('avWhitelistDialog').remove();
                showWhitelistDialog(); // Re-open dialog to refresh list
            } else {
                alert("Invalid URL. Please enter a valid URL.");
            }
        });

        document.getElementById('avCloseWhitelistBtn').addEventListener('click', function() {
            document.getElementById('avWhitelistDialog').remove();
        });

        // Add event listeners for dynamically created remove buttons
        const removeButtons = document.querySelectorAll('.avRemoveWhitelistBtn');
        removeButtons.forEach(button => {
            button.addEventListener('click', function() {
                const url = this.dataset.url;
                removeFromWhitelist(url);
                document.getElementById('avWhitelistDialog').remove();
                showWhitelistDialog(); // Re-open dialog to refresh list
            });
        });

        // Export/Import Whitelist functionality (basic)
        document.getElementById('avExportWhitelistBtn').addEventListener('click', function() {
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(whitelist));
            const downloadAnchorNode = document.createElement('a');
            downloadAnchorNode.setAttribute("href", dataStr);
            downloadAnchorNode.setAttribute("download", "av_whitelist.json");
            document.body.appendChild(downloadAnchorNode); // Required for firefox
            downloadAnchorNode.click();
            downloadAnchorNode.remove();
        });

        document.getElementById('avImportWhitelistBtn').addEventListener('click', function() {
            const input = document.createElement('input');
            input.type = 'file';

            input.onchange = e => {
                const file = e.target.files[0];
                const reader = new FileReader();
                reader.onload = readerEvent => {
                    try{
                       const content = readerEvent.target.result;
                       const importedWhitelist = JSON.parse(content);
                        if (Array.isArray(importedWhitelist)) {
                            // --- THIS IS THE FIX ---
                            const validItems = importedWhitelist
                                .filter(item => item && typeof item.url === 'string' && isValidUrl(item.url))
                                .map(item => ({ url: item.url, notes: item.notes || "" }));

                            whitelist = validItems;
                            GM_setValue(WHITELIST_KEY, JSON.stringify(whitelist));
                            document.getElementById('avWhitelistDialog').remove();
                            showWhitelistDialog(); // Re-open dialog to refresh list
                        } else {
                            alert("Invalid whitelist file.");
                        }
                    } catch (error) {
                         alert("Error parsing whitelist file.");
                    }
                }
                reader.readAsText(file);
            }
            input.click();
        });
    }

    GM_registerMenuCommand("Update Definitions", updateDefinitions);
    GM_registerMenuCommand("Manage Whitelist", showWhitelistDialog);

    //Load Library for signature validation before running the script
    initialize();
})();
