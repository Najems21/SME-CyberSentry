// Ensure we don't add the listener multiple times
if (!window.hasSmeCyberSentryListener) {
    window.hasSmeCyberSentryListener = true;

    const RISKY_EXT = /\.(exe|msi|scr|bat|cmd|pif|vbs|vbe|jse?|wsf|hta|ps1|jar|apk|xapk|dll|lnk|iso|img|vhd|dmg|pkg|zip|rar|7z|cab|reg)(\?|#|$)/i;

    // Structural signals a URL alone cannot reveal (all computed locally on the page)
    function collectSignals() {
        const abs = (u) => { try { return new URL(u, location.href).href; } catch (e) { return ""; } };

        const exeLinks = [...document.querySelectorAll('a[href]')]
            .map(a => abs(a.getAttribute('href')))
            .filter(h => RISKY_EXT.test(h))
            .slice(0, 10);

        const hiddenIframes = [...document.querySelectorAll('iframe')].filter(f => {
            const r = f.getBoundingClientRect();
            const s = getComputedStyle(f);
            return r.width <= 2 || r.height <= 2 || s.display === 'none' || s.visibility === 'hidden';
        }).length;

        const pwFields = document.querySelectorAll('input[type="password"]');
        const formActions = [...new Set([...pwFields]
            .map(p => p.form && p.form.getAttribute('action'))
            .filter(Boolean)
            .map(abs))];

        return {
            protocol: location.protocol,
            secure_context: window.isSecureContext,
            title: document.title.slice(0, 200),
            meta_refresh: [...document.querySelectorAll('meta[http-equiv="refresh" i]')]
                .map(m => m.getAttribute('content') || '').slice(0, 3),
            iframes: document.querySelectorAll('iframe').length,
            hidden_iframes: hiddenIframes,
            exe_links: exeLinks,
            download_attr_links: document.querySelectorAll('a[download]').length,
            password_fields: pwFields.length,
            form_actions: formActions
        };
    }

    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.action === "getDOM") {
            // Grab fresh text, URL and page signals exactly when the scan button is clicked
            sendResponse({
                url: window.location.href,
                text: document.body ? document.body.innerText : "",
                signals: collectSignals()
            });
        }
        // Return true to indicate we will send a response asynchronously (good practice)
        return true;
    });
}
