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

    const SHA256_RE = /^[0-9a-f]{64}$/;
    const MD5_RE = /^[0-9a-f]{32}$/;

    function hashOf(value, re) {
        const text = typeof value === 'string' ? value.toLowerCase() : '';
        return re.test(text) ? text : '';
    }

    function resultOf(item) {
        return item.centralbox && typeof item.centralbox === 'object' ? item.centralbox : null;
    }

    // Correlated hashes without a centralbox verdict (never checked, or not in
    // centralbox): [{hash, query, uploadId, file, short}]. Every SHA-256 and MD5
    // the entries name counts: hash rows ('hash') and file facts ('file_info':
    // a Spor log's FILES, an FRST Search File: entry), which are hash rows of
    // their log too. `hash` is the hash as shown, `query` the one sent: a
    // file's SHA-256 also for its MD5 (the server takes an MD5 only for a file
    // without one). A hash any entry has a report for is known already.
    function targets(items) {
        const list = (Array.isArray(items) ? items : []).filter((item) => item
            && (item.kind === 'hash' || item.kind === 'file_info'));
        const known = new Set();
        list.forEach((item) => {
            const result = resultOf(item);
            if (!result || !result.report_url) return;
            [hashOf(item.sha256, SHA256_RE), hashOf(item.md5, MD5_RE)].forEach((hash) => { if (hash) known.add(hash); });
        });
        const found = [];
        const seen = new Set();
        list.forEach((item) => {
            const sha = hashOf(item.sha256, SHA256_RE);
            const md5 = hashOf(item.md5, MD5_RE);
            const uploadId = String(item.upload_id || '');
            if (!/^[A-Za-z0-9_-]+$/.test(uploadId) || (sha && known.has(sha))) return;
            // A hash row names its file by one hash; file facts show both.
            const shown = item.kind === 'hash' ? [sha || md5] : [sha, md5];
            shown.forEach((hash) => {
                if (!hash || seen.has(hash) || known.has(hash)) return;
                seen.add(hash);
                // The file the hash belongs to: a line can name several (its
                // own file, a script in its command line, ...).
                const file = typeof item.file === 'string' ? item.file : '';
                const short = (hash.length === 64 ? 'SHA-256 ' : 'MD5 ') + hash.slice(0, 12) + '…';
                found.push({ hash, query: sha || md5, uploadId, file, short: file ? `of ${file} (${short})` : short });
            });
        });
        return found;
    }

    // The hash a lookup asks centralbox about.
    function queryOf(target) {
        return target.query || target.hash;
    }

    function verdictText(verdict) {
        if (!verdict || typeof verdict !== 'object') return '';
        if (verdict.state === 'unknown') return 'not in centralbox';
        if (verdict.verdict === 'malicious') return 'centralbox: ' + (verdict.family || verdict.malware_type || 'malicious');
        return verdict.verdict ? 'centralbox: ' + verdict.verdict : '';
    }

    function post(url, payload) {
        return Fenris.requestJson(url, { body: payload });
    }

    // "check this hash": the stored or cached answer. urls: {check}.
    async function check(target, urls, onProgress) {
        onProgress('centralbox: checking…');
        const { status, body } = await post(urls.check, { sha256: queryOf(target), upload_id: target.uploadId });
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
        const { status, body } = await post(urls.fresh, { sha256: queryOf(target), upload_id: target.uploadId });
        if (status !== 200 || !body || body.ok !== true) {
            const message = body && typeof body.message === 'string' && body.message ? body.message : 'the lookup could not be started';
            return { message: 'centralbox: ' + message, refresh: false };
        }
        if (body.state !== 'running') {
            return { message: verdictText(body.verdict) || 'centralbox: ' + body.state, refresh: true };
        }
        onProgress('centralbox: looking up…');
        const url = urls.freshStatus.replace('0'.repeat(64), encodeURIComponent(queryOf(target)));
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

    // A circle with an up arrow, drawn (no font has a dependable glyph for
    // it): shown instead of the circled i while a line's correlations hold a
    // hash a lookup can be started for. Constant markup, no data in it; CSS
    // class .cb-lookup-icon sizes it like the glyph it replaces.
    // Matched against the font's circled i (rendered side by side): a light
    // circle, the arrow about as heavy as the glyph's i; sized 1.2em in CSS.
    const ICON_SVG = '<svg class="cb-lookup-icon" viewBox="0 0 16 16" aria-hidden="true">'
        + '<circle cx="8" cy="8" r="6.3" fill="none" stroke="currentColor" stroke-width="1.1"/>'
        + '<path d="M8 11.4V5M5.6 7.4L8 5l2.4 2.4" fill="none" stroke="currentColor" stroke-width="1.7" '
        + 'stroke-linecap="round" stroke-linejoin="round"/></svg>';

    // Puts the lookup icon or the circled i into an info button.
    function setIcon(button, lookup) {
        if (lookup) {
            button.innerHTML = ICON_SVG;
            button.dataset.lookup = '1';
        } else {
            button.textContent = 'ⓘ';
            delete button.dataset.lookup;
        }
    }

    return { targets, verdictText, check, fresh, setIcon };
})();
