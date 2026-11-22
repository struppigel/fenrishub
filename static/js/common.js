/* Helpers every page shares: CSRF token, JSON requests, clipboard, saved settings.
 *
 * Loaded from base.html's <head>, before any page script, so inline scripts may
 * use `Fenris.*` right away. Plain globals, no modules (there is no build step).
 */
window.Fenris = (function () {
    'use strict';

    /* Django's CSRF cookie (readable by scripts), else a form's hidden field. */
    function csrfToken() {
        const match = /(?:^|;\s*)csrftoken=([^;]+)/.exec(document.cookie || '');
        if (match) return decodeURIComponent(match[1]);
        const field = document.querySelector('input[name="csrfmiddlewaretoken"]');
        return field ? field.value : '';
    }

    function jsonInit(method, body, signal) {
        const init = {
            method,
            credentials: 'same-origin',
            headers: { Accept: 'application/json', 'X-CSRFToken': csrfToken() },
        };
        if (body !== undefined) {
            init.headers['Content-Type'] = 'application/json';
            init.body = JSON.stringify(body);
        }
        if (signal) init.signal = signal;
        return init;
    }

    /* `{status, body}` for a JSON request; never throws. `status` is 0 when the
     * request failed outright, `body` null when the reply was not a JSON object. */
    async function requestJson(url, { method = 'POST', body, signal } = {}) {
        try {
            const response = await fetch(url, jsonInit(method, body, signal));
            let data = null;
            try {
                data = await response.json();
            } catch (error) {
                data = null;
            }
            return { status: response.status, body: data && typeof data === 'object' ? data : null };
        } catch (error) {
            return { status: 0, body: null };
        }
    }

    /* POST `body` as JSON and resolve with the parsed reply. A non-2xx reply
     * rejects with an Error carrying the server's `error` message, else
     * `errorMessage` (and the reply as `error.data`); an aborted request
     * rejects with the AbortError. */
    async function postJson(url, body, { signal, errorMessage } = {}) {
        const response = await fetch(url, jsonInit('POST', body, signal));
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            const message = (data && data.error) || errorMessage || `Request failed (${response.status}).`;
            const error = new Error(message);
            error.status = response.status;
            error.data = data;
            throw error;
        }
        return data;
    }

    /* Copy `value` to the clipboard; resolves true on success. Falls back to a
     * hidden textarea where the async Clipboard API is missing or refused. */
    async function copyText(value) {
        if (typeof value !== 'string') return false;
        try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                await navigator.clipboard.writeText(value);
                return true;
            }
        } catch (error) {
            // fall through to the textarea fallback
        }
        try {
            const ta = document.createElement('textarea');
            ta.value = value;
            ta.setAttribute('readonly', '');
            ta.style.position = 'fixed';
            ta.style.left = '-9999px';
            document.body.appendChild(ta);
            ta.select();
            const ok = document.execCommand('copy');
            document.body.removeChild(ta);
            return ok;
        } catch (error) {
            return false;
        }
    }

    /* Show `label` on `button` for a moment, then restore its text. */
    function flashButton(button, label = 'copied', ms = 1200) {
        if (!button) return;
        if (button.dataset.flashOriginal === undefined) {
            button.dataset.flashOriginal = button.textContent;
        }
        button.textContent = label;
        clearTimeout(button._fenrisFlashTimer);
        button._fenrisFlashTimer = setTimeout(() => {
            button.textContent = button.dataset.flashOriginal;
            delete button.dataset.flashOriginal;
        }, ms);
    }

    /* Copy `value` and confirm on `button`; resolves true on success. */
    async function copyWithFeedback(value, button, label = 'copied') {
        const ok = await copyText(value);
        if (ok) flashButton(button, label);
        return ok;
    }

    /* Briefly mark `element` with `className` (restarting the CSS animation). */
    function flashClass(element, className = 'hl-copied', ms = 900) {
        element.classList.remove(className);
        void element.offsetWidth;
        element.classList.add(className);
        setTimeout(() => element.classList.remove(className), ms);
    }

    /* Open `url` in a new tab without giving it a handle on this page. */
    function openUrl(url) {
        if (url) window.open(url, '_blank', 'noopener,noreferrer');
    }

    /* Lookups of URLs, domains and certificates, shared by the analyzer's
     * menus (log_analyzer/analysis.js), the log page and the correlation
     * info box. A log's own URL is never opened: it only goes, escaped, into
     * these lookup addresses. */
    // "hxxps://" (defanged, common in malware reports) -> "https://".
    function refangUrl(value) {
        return String(value || '').replace(/^hxxp(s?):\/\//i, 'http$1://');
    }

    // A URL as a log writes it, ready for a lookup: refanged, without a
    // "blob:" prefix (the page's own address follows it), a "…" where the log
    // cut it, or punctuation of the text around it. `cut`: it was cut.
    // `host`: its host name, also for Spor's "host/path" without scheme.
    function lookupUrl(text) {
        let value = String(text || '').trim();
        const cut = /…$/.test(value);
        value = value.replace(/…+$/, '').replace(/^blob:/i, '').replace(/[;,.:!?]+$/, '');
        value = refangUrl(value);
        let host = '';
        try {
            host = /^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? new URL(value).hostname : '';
        } catch (error) {
            host = '';
        }
        if (!host) host = value.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').split(/[\/?#]/)[0].replace(/:\d+$/, '');
        return { value, cut, host: host.toLowerCase() };
    }

    const THUMBPRINT_RE = /^[0-9A-Fa-f]{40}$/;
    const virusTotal = {
        urlSearch: (url) => 'https://www.virustotal.com/gui/search?query=' + encodeURIComponent(refangUrl(url)),
        domain: (host) => 'https://www.virustotal.com/gui/domain/' + encodeURIComponent(host),
        ip: (ip) => 'https://www.virustotal.com/gui/ip-address/' + encodeURIComponent(ip),
        // VT Intelligence: the files whose signature names this certificate
        // (its SHA-1 thumbprint); '' for anything but 40 hex digits.
        thumbprint: (thumb) => (THUMBPRINT_RE.test(String(thumb || '').trim())
            ? 'https://www.virustotal.com/gui/search?query='
              + encodeURIComponent('signature:' + String(thumb).trim().toUpperCase()) + '&type=files'
            : ''),
    };
    const urlscan = {
        search: (url) => 'https://urlscan.io/search/#' + encodeURIComponent(refangUrl(url)),
        domain: (host) => 'https://urlscan.io/domain/' + encodeURIComponent(host),
        ip: (ip) => 'https://urlscan.io/ip/' + encodeURIComponent(ip),
    };
    const whoIs = {
        domain: (host) => 'https://who.is/whois/' + encodeURIComponent(host),
        ip: (ip) => 'https://who.is/whois-ip/ip-address/' + encodeURIComponent(ip),
    };
    const abuseIpDb = {
        ip: (ip) => 'https://www.abuseipdb.com/check/' + encodeURIComponent(ip),
    };

    // A URL's host is an IP address ("1.2.3.4", "[::1]" without its brackets).
    const IP_HOST_RE = /^(?:\d{1,3}(?:\.\d{1,3}){3}|\[?[0-9a-f:]*:[0-9a-f:.]*\]?)$/i;

    // `ip` / `domain` service URL for the host of URL text `v`, '' without a host.
    function hostLookup(v, ip, domain) {
        const host = lookupUrl(v).host;
        if (!host) return '';
        return IP_HOST_RE.test(host) ? ip(host.replace(/^\[|\]$/g, '')) : domain(host);
    }

    /* The one set of lookups of each kind, for the analyzer's menus
     * (LOOKUP_KINDS), the log page's menus and the correlation info box.
     * Items: { label, url(value) -> lookup address ('' = not for this value),
     * detail(value) -> what it looks up when that is not the value itself }. */
    const lookups = {
        url: [
            { label: 'virustotal', url: (v) => virusTotal.urlSearch(lookupUrl(v).value) },
            { label: 'virustotal domain', url: (v) => hostLookup(v, virusTotal.ip, virusTotal.domain),
              detail: (v) => lookupUrl(v).host },
            { label: 'who.is', url: (v) => hostLookup(v, whoIs.ip, whoIs.domain), detail: (v) => lookupUrl(v).host },
            { label: 'urlscan.io', url: (v) => urlscan.search(lookupUrl(v).value) },
        ],
        domain: [
            { label: 'virustotal', url: (v) => virusTotal.domain(v) },
            { label: 'who.is', url: (v) => whoIs.domain(v) },
            { label: 'urlscan.io', url: (v) => urlscan.domain(v) },
        ],
        ip: [
            { label: 'virustotal', url: (v) => virusTotal.ip(v) },
            { label: 'who.is', url: (v) => whoIs.ip(v) },
            { label: 'abuseipdb', url: (v) => abuseIpDb.ip(v) },
            { label: 'urlscan.io', url: (v) => urlscan.ip(v) },
        ],
    };

    // [{ label, href, detail }] of the lookups of `kind` for `value` ('' detail:
    // the value itself), without those that don't apply to it.
    function lookupLinks(kind, value) {
        return (lookups[kind] || [])
            .map((item) => ({ label: item.label, href: item.url(value), detail: item.detail ? item.detail(value) : '' }))
            .filter((link) => link.href);
    }

    /* localStorage that never throws (private windows, disabled storage). */
    const storage = {
        get(key, fallback = null) {
            try {
                const value = window.localStorage.getItem(key);
                return value === null ? fallback : value;
            } catch (error) {
                return fallback;
            }
        },
        /* Returns false when the value could not be stored (quota, disabled). */
        set(key, value) {
            try {
                window.localStorage.setItem(key, String(value));
                return true;
            } catch (error) {
                return false;
            }
        },
        remove(key) {
            try {
                window.localStorage.removeItem(key);
            } catch (error) {
                // ignore
            }
        },
        /* A remembered on/off setting, stored as '1' / '0'. */
        flag(key, fallback = false) {
            const value = storage.get(key);
            return value === null ? fallback : value === '1';
        },
        setFlag(key, on) {
            storage.set(key, on ? '1' : '0');
        },
    };

    /* Classification status codes, as fixlist/status_types.py defines them
     * (a test keeps the two in step): CSS class, short label, precedence. */
    const status = {
        cssClass: {
            B: 'status-b', P: 'status-p', C: 'status-c', '!': 'status-w', A: 'status-a',
            G: 'status-g', S: 'status-s', I: 'status-i', J: 'status-j', '?': 'status-unknown',
        },
        label: {
            B: 'malware', P: 'potentially unwanted', C: 'clean', '!': 'warning', A: 'alert',
            G: 'grayware', S: 'security', I: 'informational', J: 'junk', '?': 'unknown',
        },
        precedence: ['B', 'P', 'C', 'A', '!', 'G', 'S', 'I', 'J', '?'],
        /* The colour suffix of a code ('B' -> 'b', '!' -> 'w', unknown -> 'unknown'). */
        paint(code) {
            return (status.cssClass[code] || 'status-unknown').replace('status-', '');
        },
    };

    /* Spor writes characters that cannot be seen as "<U+00A0>" and bidi
     * overrides as "<RLO>" ('<' is never part of a Windows path). The real
     * path, e.g. for a fixlist; null when there is no such marker. */
    // Markers of characters no Windows name holds (control characters,
    // surrogates, \ / : * ? " < > |) stay as written, as in frst_extractors.
    function realPath(text) {
        if (!text || !/<U\+[0-9A-Fa-f]{4,6}>|<RLO>/.test(text)) return null;
        return text.replace(/<U\+([0-9A-Fa-f]{4,6})>|<RLO>/g, (all, hex) => {
            if (!hex) return '‮';
            const code = parseInt(hex, 16);
            if (code < 0x20 || (code >= 0xD800 && code <= 0xDFFF) || code > 0x10FFFF) return all;
            const ch = String.fromCodePoint(code);
            return '\\/:*?"<>|'.includes(ch) ? all : ch;
        });
    }

    return {
        status,
        csrfToken, requestJson, postJson,
        copyText, flashButton, copyWithFeedback, flashClass,
        openUrl, storage, realPath,
        refangUrl, lookupUrl, virusTotal, urlscan, whoIs, abuseIpDb, lookups, lookupLinks,
    };
})();
