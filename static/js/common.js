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
    };
})();
