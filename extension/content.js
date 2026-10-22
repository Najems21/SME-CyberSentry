// Ensure we don't add the listener multiple times
if (!window.hasSmeCyberSentryListener) {
    window.hasSmeCyberSentryListener = true;

    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.action === "getDOM") {
            // Grab fresh text and URL exactly when the scan button is clicked
            const pageText = document.body.innerText;
            const pageUrl = window.location.href;
            
            sendResponse({ url: pageUrl, text: pageText });
        }
        // Return true to indicate we will send a response asynchronously (good practice)
        return true; 
    });
}