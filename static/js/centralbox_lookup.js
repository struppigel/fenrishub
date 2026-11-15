// centralbox lookups of correlated hashes, shared by the analyzer
// (log_analyzer/case_correlations.js) and the log page (view_uploaded_log.html).
// Each lookup asks the same endpoints as the hash menus, with the related log
// that holds the hash (the server only accepts a hash of that log). Progress
// goes to a callback; the result says what to show and whether the
// correlations should be fetched again. No build step: one global.
const CentralboxLookup = (function () {
    'use strict';

    const FRESH_POLL_MS = 4000;
    const FRESH_POLL_TRIES = 30;

    // Correlated hashes without a centralbox verdict (never checked, or not in
    // centralbox): [{hash, uploadId, short}]. Known hashes have a report entry.
    function targets(items) {
        const found = [];
        const seen = new Set();
        (Array.isArray(items) ? items : []).forEach((item) => {
            if (!item || item.kind !== 'hash') return;
            const result = item.centralbox && typeof item.centralbox === 'object' ? item.centralbox : null;
            if (result && result.report_url) return;
            const sha = typeof item.sha256 === 'string' && /^[0-9a-f]{64}$/.test(item.sha256) ? item.sha256 : '';
            const md5 = typeof item.md5 === 'string' && /^[0-9a-f]{32}$/.test(item.md5) ? item.md5 : '';
            const hash = sha || md5;
            const uploadId = String(item.upload_id || '');
            if (!hash || seen.has(hash) || !/^[A-Za-z0-9_-]+$/.test(uploadId)) return;
            seen.add(hash);
            found.push({ hash, uploadId, short: (sha ? 'SHA-256 ' : 'MD5 ') + hash.slice(0, 12) + '…' });
        });
        return found;
    }

    function verdictText(verdict) {
        if (!verdict || typeof verdict !== 'object') return '';
        if (verdict.state === 'unknown') return 'not in centralbox';
        if (verdict.verdict === 'malicious') return 'centralbox: ' + (verdict.family || verdict.malware_type || 'malicious');
        return verdict.verdict ? 'centralbox: ' + verdict.verdict : '';
    }

    // Django's CSRF cookie (readable by scripts), else a form's hidden field.
    function csrfToken() {
        const match = /(?:^|;\s*)csrftoken=([^;]+)/.exec(document.cookie || '');
        if (match) return decodeURIComponent(match[1]);
        const field = document.querySelector('input[name="csrfmiddlewaretoken"]');
        return field ? field.value : '';
    }

    async function post(url, payload) {
        try {
            const response = await fetch(url, {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'X-CSRFToken': csrfToken() },
                body: JSON.stringify(payload),
            });
            let body = null;
            try {
                body = await response.json();
            } catch (error) {
                body = null;
            }
            return { status: response.status, body };
        } catch (error) {
            return { status: 0, body: null };
        }
    }

    // "check this hash": the stored or cached answer. urls: {check}.
    async function check(target, urls, onProgress) {
        onProgress('centralbox: checking…');
        const { status, body } = await post(urls.check, { sha256: target.hash, upload_id: target.uploadId });
        if (status !== 200 || !body || typeof body !== 'object') {
            return { message: 'centralbox: the check failed, try again later', refresh: false };
        }
        const message = verdictText(body.verdict)
            || (body.unknown ? 'not in centralbox'
                : body.available ? 'centralbox: no answer yet, try again later' : 'centralbox is not available right now');
        return { message, refresh: true };
    }

    // "run fresh lookup": start it, then follow it until centralbox is done.
    // urls: {fresh, freshStatus (with 64 zeros for the hash)}.
    async function fresh(target, urls, onProgress) {
        onProgress('centralbox: starting a fresh lookup…');
        const { status, body } = await post(urls.fresh, { sha256: target.hash, upload_id: target.uploadId });
        if (status !== 200 || !body || body.ok !== true) {
            const message = body && typeof body.message === 'string' && body.message ? body.message : 'the lookup could not be started';
            return { message: 'centralbox: ' + message, refresh: false };
        }
        if (body.state !== 'running') {
            return { message: verdictText(body.verdict) || 'centralbox: ' + body.state, refresh: true };
        }
        onProgress('centralbox: looking up…');
        const url = urls.freshStatus.replace('0'.repeat(64), encodeURIComponent(target.hash));
        for (let attempt = 0; attempt < FRESH_POLL_TRIES; attempt += 1) {
            await new Promise((resolve) => setTimeout(resolve, FRESH_POLL_MS));
            let state = null;
            try {
                const response = await fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json' } });
                state = response.ok && !response.redirected ? await response.json() : null;
            } catch (error) {
                state = null;
            }
            if (state && typeof state === 'object' && state.state && state.state !== 'running') {
                const message = state.state === 'error'
                    ? 'centralbox: the lookup failed, try again after the cooldown'
                    : verdictText(state.verdict) || (state.state === 'not_found' ? 'not in centralbox' : 'centralbox: done');
                return { message, refresh: true };
            }
        }
        return { message: 'centralbox: still running; reload later', refresh: false };
    }

    return { targets, verdictText, check, fresh };
})();
