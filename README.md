# BrowserGuard

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Author](https://img.shields.io/badge/Author-Johnathon%20M.%20Horner-blue)](https://github.com/jhorner6511)

## Description

BrowserGuard is a Tampermonkey userscript designed to provide an additional layer of security within your web browser. It acts as an in-browser antivirus, focusing on proactively blocking malicious scripts and content before they can harm your system. While it is not intended to replace a dedicated desktop antivirus, BrowserGuard significantly enhances your online safety by intercepting and analyzing web page content in real-time.

## Key Features

*   **Proactive Script Blocking:** By injecting itself into the browser at the `document-start` phase, BrowserGuard intercepts script execution attempts before they can be parsed by the browser. This allows the script to effectively prevent malicious code from running.
*   **Signature-Based Threat Detection:** BrowserGuard utilizes a continuously updated database of virus definitions (malicious code patterns) to identify potential threats. These definitions are compared against loaded web page content to detect suspicious or known-malicious code.
*   **Asymmetric Signature Verification:** Definition updates are secured using asymmetric cryptography. The script verifies the digital signature of each definition update against a trusted public key, ensuring that the definitions have not been tampered with during transmission or by a malicious third party. This process includes fingerprint verification, to prevent Man-In-The-Middle (MITM) attacks.
*   **Content Security Policy (CSP) Heuristics:** BrowserGuard simulates some Content Security Policy (CSP) protections by detecting and flagging suspicious coding patterns such as use of `eval()` or attempts to access global objects like `window.top` (sandbox escapes).
*   **Comprehensive Scanning:** BrowserGuard scans various aspects of web pages for potential threats, including:
    *   Inline JavaScript code
    *   External JavaScript files loaded via `<script>` tags
    *   Inline event handlers (e.g., `onclick`, `onmouseover`)
    *   Content loaded within `<iframe>` elements (with CORS limitations)
    *   External CSS files loaded via `<link>` tags
    *   JSON responses from `XMLHttpRequest` (XHR) and `fetch` API calls
    *   Code within `eval()` calls
*   **Configurable Scanning:** Users can enable or disable scanning of JSON responses, XHR/Fetch calls, and iframe content directly from the dashboard UI.
*   **Quarantine:** High-risk scripts are "quarantined" instead of simply removed from the DOM. The script is prevented from running, and is hidden.
*   **Performance Optimization:** The script utilizes precompiled regular expressions and in-memory caching to minimize performance impact during scanning. It employs a synchronous hashing function in the `appendChild` hook to avoid blocking the main thread.
*   **Whitelist (Site Exceptions):** Users can add trusted websites to a whitelist. Content from whitelisted sites will be skipped during the scanning process, improving performance. Whitelist entries can be exported and imported for portability.
*   **Dashboard UI:** A floating dashboard provides real-time information about BrowserGuard's status, including:
    *   Current status (scanning, paused, updated, etc.)
    *   Number of threats blocked, detected, and ignored
    *   Timestamp of the last definition update
    *   "Pause Protection" toggle to temporarily disable scanning
    *   "Auto-block High Risk" toggle to automatically quarantine high-risk scripts
*   **Logging:** All security events are logged with timestamps and severity levels (info, warn, error). Logs are stored locally and periodically saved to prevent bloating storage.
*   **User-Friendly Controls:** A manual update button allows users to immediately refresh the virus definitions.
*   **Offline Mode:** The script can run entirely from cached definitions when the user is offline, providing continuous protection.

## How it Works

1.  **Initialization:** Upon loading a web page, BrowserGuard initializes itself by:
    *   Loading previously cached virus definitions
    *   Downloading and verifying the latest definitions from a remote source
    *   Precompiling regular expressions from the loaded definitions for efficient scanning
    *   Overriding core JavaScript functions such as `Node.prototype.appendChild` and `XMLHttpRequest.prototype.open` to intercept script execution and network requests
    *   Creating the floating dashboard UI
2.  **Content Interception:** BrowserGuard intercepts script execution attempts and network requests before they reach the browser's core engine.
3.  **Threat Analysis:** Intercepted content is compared against the loaded virus definitions using regular expression matching.
4.  **Action & Reporting:** If a match is found, BrowserGuard takes appropriate action:
    *   High-risk threats are automatically quarantined or blocked (based on user preference)
    *   Medium- and low-risk threats are logged for user awareness
    *   Events are logged to the console and displayed in the dashboard
5.  **Continuous Monitoring:** A MutationObserver monitors the DOM for dynamically added content, ensuring that newly inserted scripts and elements are also scanned for potential threats.

## Installation

1.  Install a userscript manager such as [Tampermonkey](https://www.tampermonkey.net/) in your browser.
2.  Copy the code from `BrowserGuard.user.js`.
3.  Paste the code into a new script in Tampermonkey.
4.  Save the script.

## Configuration

*   **`DEFINITIONS_URL`:**  URL of the virus definitions file (JSON format).  **IMPORTANT:** This file **must** be hosted on a secure (HTTPS) server.
*   **`PUBLIC_KEY_URL`:**  URL of the public key file (PEM format). Used to verify the signature of the definitions file.
*   **`PUBLIC_KEY_FINGERPRINT`:** The SHA-256 fingerprint (hash) of your public key. Setting this hardcoded value helps protect against MITM attacks during key retrieval.
*   Configure whitelisting, auto-blocking, and scanning options through the dashboard UI.

## Dependencies

*   [Tampermonkey](https://www.tampermonkey.net/) or similar userscript manager
*   [jsrsasign](https://kjur.github.io/jsrsasign/) Javascript library for signature validation. This is automatically fetched by the userscript.

## Important Notes

*   BrowserGuard is not a substitute for a dedicated desktop antivirus solution. It is designed to provide an extra layer of security within the browser environment.
*   Users are responsible for ensuring the integrity and trustworthiness of the virus definitions source and the public key.
*   The effectiveness of BrowserGuard depends on the quality and comprehensiveness of the virus definitions.
*   Be careful and conduct a security review before loading.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support the Project

If you find BrowserGuard useful and want to support ongoing development, consider donating to the following address:

*   **BTC:** `bc1quje84m4uzu8cc5hdk5m0knjq9mrgfz4nhl09r2`
