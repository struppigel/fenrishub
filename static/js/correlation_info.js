/* The correlation info box: everything the other logs of a case say about the
 * file(s) of one line (fixlist/case_correlations.py), in a dialog over the
 * page. Shared by the log analyzer (log_analyzer/case_correlations.js) and the
 * uploaded log page, so both show the same thing.
 *
 * Per file: its hashes (copy, VirusTotal, centralbox result, check / fresh
 * lookup), facts about the file (signature, version, company, ... from Spor
 * and FRST Search), detections and fixlist results, and its activity (Spor's
 * timeline and module sections, shortcuts, FRST Search hits), newest first.
 * Every row links to the log line it comes from.
 *
 * CorrelationInfo.open({
 *     lineText,            the line, shown on top
 *     lineStatus,          the line's verdict letter as the page shows it ('' for none)
 *     lineIsFrst,          false when the line is not an FRST / Addition line
 *                          (no FRST-only token colours); default true
 *     getEntries(),        the line's entries now (called again after a lookup)
 *     isOwn(entry),        an entry of the shown log itself
 *     scope, name,         'case' / 'user' and the forum user (header text)
 *     status,              the line's correlation status letter ('' for none)
 *     onJump(lineNo, entry), go to a line of the shown log (own entries)
 *     lookup: {canLookup, urls: {check, fresh, freshStatus}},
 *     refresh(),           fetch the correlations again (after a lookup)
 *     trigger,             focus returns here when the box closes
 * })
 * Needs correlation_format.js; centralbox_lookup.js for the lookups;
 * log_tokens.js (+ log_highlight.css) for the log page's token colours. */
window.CorrelationInfo = (function () {
    const Format = () => window.CorrelationFormat;
    const VT_FILE_URL = 'https://www.virustotal.com/gui/file/';
    const VT_URL_RE = /^https:\/\/(?:www\.)?virustotal\.com\/[^\s"'<>]*$/i;
    const SEVERITIES = ['b', 'p', 'g', 'w', 'c', 'i', 'j'];
    const SIGNATURE_SEVERITY = { valid: 'c', unsigned: 'w', invalid: 'b', revoked: 'b', expired: 'b' };
    // file_info facts in the order they are shown.
    const FACTS = [
        ['signature', 'signature'], ['signer', 'signer'], ['thumbprint', 'thumbprint'], ['note', 'note'],
        ['version', 'version'], ['description', 'description'], ['product', 'product'], ['company', 'company'],
        ['original_name', 'original name'], ['file_status', 'status'], ['size', 'size (bytes)'],
        ['created', 'created'], ['modified', 'modified'], ['attributes', 'attributes'], ['signed', 'signed'],
    ];

    let modal = null;
    let dialog = null;
    let titleEl = null;
    let bodyEl = null;
    let state = null;

    function el(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined && text !== null && text !== '') node.textContent = String(text);
        return node;
    }

    function str(value) {
        return typeof value === 'string' ? value : '';
    }

    function sevClass(severity) {
        return SEVERITIES.includes(severity) ? 'cinfo-sev-' + severity : '';
    }

    // Log text in the log page's token colours (log_tokens.js), plain text
    // without it; `frst` for FRST / Addition lines. The text stays the text.
    function appendTokens(node, text, frst = false) {
        const value = str(text);
        if (window.LogTokens && typeof window.LogTokens.append === 'function') window.LogTokens.append(node, value, frst);
        else node.appendChild(document.createTextNode(value));
        return node;
    }

    function tokenized(tag, className, text, frst = false) {
        return appendTokens(el(tag, className), text, frst);
    }

    // The colour suffix of a rule status letter ('B' -> 'b', '!' -> 'w'), '' for none.
    function statusPaint(letter) {
        return Format().STATUS_CLASS[str(letter)] || '';
    }

    // The status letter in front of a line, left out of a copied selection.
    function statusLetter(letter) {
        const paint = statusPaint(letter);
        return paint ? el('span', 'cinfo-status-letter cinfo-sev-' + paint, letter) : null;
    }

    // The strongest of the given status letters (rule precedence), '' for none.
    function worstStatus(letters) {
        const order = (window.Fenris && Fenris.status && Fenris.status.precedence) || [];
        const known = letters.filter((letter) => statusPaint(letter));
        known.sort((a, b) => order.indexOf(a) - order.indexOf(b));
        return known[0] || '';
    }

    // A log line in a box: the status letter, then the line in token colours;
    // the box's left edge in the status colour.
    function lineNode(text, status, frst) {
        const paint = statusPaint(status);
        const node = el('pre', 'cinfo-line' + (paint ? ' cinfo-edge-' + paint : ''));
        const letter = statusLetter(status);
        if (letter) node.appendChild(letter);
        node.appendChild(tokenized('span', 'cinfo-line-text', text, frst));
        return node;
    }

    function ensure() {
        if (modal && document.body.contains(modal)) return;
        modal = el('div', 'cinfo-modal');
        modal.hidden = true;
        const backdrop = el('div', 'cinfo-backdrop');
        backdrop.addEventListener('click', close);
        dialog = el('div', 'cinfo-dialog');
        dialog.setAttribute('role', 'dialog');
        dialog.setAttribute('aria-modal', 'true');
        dialog.setAttribute('aria-labelledby', 'cinfoTitle');
        dialog.tabIndex = -1;
        const head = el('div', 'cinfo-head');
        titleEl = el('h2', 'cinfo-title', 'what other logs say about this line');
        titleEl.id = 'cinfoTitle';
        const closeButton = el('button', 'cinfo-close', '×');
        closeButton.type = 'button';
        closeButton.setAttribute('aria-label', 'close');
        closeButton.addEventListener('click', close);
        head.append(titleEl, closeButton);
        bodyEl = el('div', 'cinfo-body');
        const foot = el('div', 'cinfo-foot');
        const doneButton = el('button', 'cinfo-done', 'close');
        doneButton.type = 'button';
        doneButton.addEventListener('click', close);
        foot.appendChild(doneButton);
        dialog.append(head, bodyEl, foot);
        modal.append(backdrop, dialog);
        // Keys stay in the box: the page's own Escape / Tab handlers (e.g. the
        // analyzer's line inspector underneath) must not see them.
        modal.addEventListener('keydown', (event) => {
            if (event.key === 'Escape') {
                event.preventDefault();
                event.stopPropagation();
                close();
            } else if (event.key === 'Tab') {
                event.stopPropagation();
                trapTab(event);
            }
        });
        document.body.appendChild(modal);
    }

    function trapTab(event) {
        const focusable = Array.from(dialog.querySelectorAll('a[href], button:not([disabled])'))
            .filter((node) => node.offsetParent !== null);
        if (!focusable.length) {
            event.preventDefault();
            dialog.focus();
            return;
        }
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (event.shiftKey && (document.activeElement === first || document.activeElement === dialog)) {
            event.preventDefault();
            last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
            event.preventDefault();
            first.focus();
        }
    }

    function isOpen() {
        return Boolean(modal) && !modal.hidden;
    }

    function open(options) {
        ensure();
        state = Object.assign({ messages: {}, busy: {} }, options || {});
        render();
        modal.hidden = false;
        dialog.scrollTop = 0;
        bodyEl.scrollTop = 0;
        dialog.focus();
    }

    function close() {
        if (!isOpen()) return;
        modal.hidden = true;
        const trigger = state && state.trigger;
        state = null;
        if (trigger && trigger.isConnected && typeof trigger.focus === 'function') trigger.focus();
    }

    function entries() {
        try {
            const list = state && typeof state.getEntries === 'function' ? state.getEntries() : [];
            return Array.isArray(list) ? list.filter((entry) => entry && typeof entry === 'object') : [];
        } catch (error) {
            return [];
        }
    }

    function isOwn(entry) {
        return Boolean(state && typeof state.isOwn === 'function' && state.isOwn(entry));
    }

    // ------------------------------------------------------------------
    // Sources: which log a row comes from, and a link to its line
    // ------------------------------------------------------------------

    // Which log a row comes from: "this log" or its type, and "other system?".
    function sourceLabel(wrap, entry) {
        const own = isOwn(entry);
        wrap.appendChild(el('span', 'cinfo-src-type', own ? 'this log' : str(entry.log_type) || 'log'));
        if (!own && entry.system === 'different') wrap.appendChild(el('span', 'cinfo-src-other', 'other system?'));
        return wrap;
    }

    // "L<n>": jumps to the line of the shown log, or opens the other log at
    // the line in a new tab. null when there is nowhere to go.
    function lineLink(entry) {
        const lineNo = Number(entry.anchor_line_no || entry.line_no);
        const label = Number.isInteger(lineNo) && lineNo > 0 ? 'L' + lineNo : 'open';
        if (isOwn(entry)) {
            const jump = el('button', 'cinfo-link cinfo-jump', label);
            jump.type = 'button';
            jump.title = 'go to the line in this log';
            jump.addEventListener('click', () => {
                const onJump = state && state.onJump;
                close();
                if (typeof onJump === 'function') onJump(lineNo, entry);
            });
            return jump;
        }
        const url = Format().logUrl(entry);
        if (!url) return null;
        const link = el('a', 'cinfo-link', label);
        link.href = url;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        link.title = `open the ${str(entry.log_type) || 'log'} at this line`;
        return link;
    }

    function sourceNode(entry) {
        const wrap = sourceLabel(el('span', 'cinfo-src'), entry);
        const link = lineLink(entry);
        if (link) wrap.appendChild(link);
        return wrap;
    }

    function row(className) {
        return el('li', 'cinfo-row' + (className ? ' ' + className : ''));
    }

    function section(parent, title) {
        const block = el('div', 'cinfo-block');
        block.appendChild(el('h4', 'cinfo-block-title', title));
        const list = el('ul', 'cinfo-list');
        block.appendChild(list);
        parent.appendChild(block);
        return list;
    }

    // ------------------------------------------------------------------
    // Hashes
    // ------------------------------------------------------------------

    function collectHashes(group) {
        const hashes = new Map();
        const add = (value, kind, entry) => {
            const hash = str(value).toLowerCase();
            if (!hash) return;
            if (!hashes.has(hash)) hashes.set(hash, { hash, kind, entries: [], centralbox: null });
            const item = hashes.get(hash);
            item.entries.push(entry);
            if (entry.centralbox && typeof entry.centralbox === 'object' && !item.centralbox) item.centralbox = entry.centralbox;
        };
        group.entries.forEach((entry) => {
            if (entry.kind === 'hash') {
                const sha = Format().sha256Of(entry);
                add(sha || Format().md5Of(entry), sha ? 'SHA-256' : 'MD5', entry);
            } else if (entry.kind === 'file_info') {
                if (/^[0-9a-f]{64}$/.test(str(entry.sha256))) add(entry.sha256, 'SHA-256', entry);
                if (/^[0-9a-f]{32}$/.test(str(entry.md5))) add(entry.md5, 'MD5', entry);
                if (/^[0-9a-f]{40}$/.test(str(entry.sha1))) {
                    add(entry.sha1, entry.source === 'spor_amcache' || entry.sha256 || entry.md5 ? 'SHA-1 (Amcache)' : 'SHA-1', entry);
                }
            }
        });
        return [...hashes.values()];
    }

    function centralboxText(result) {
        if (!result) return '';
        if (result.state === 'unknown') return 'not in centralbox' + (result.checked_at ? ` (checked ${str(result.checked_at).slice(0, 10)})` : '');
        const parts = [result.verdict ? 'centralbox: ' + result.verdict : 'centralbox result'];
        if (result.family) parts.push(result.family);
        if (result.malware_type) parts.push(result.malware_type);
        if (result.threat_score !== undefined && result.threat_score !== null && result.threat_score !== '') {
            parts.push('score ' + result.threat_score);
        }
        if (result.checked_at) parts.push('checked ' + str(result.checked_at).slice(0, 10));
        return parts.join(Format().DOT);
    }

    function lookupTargets(group) {
        const lookup = state && state.lookup;
        if (!lookup || !lookup.canLookup || typeof CentralboxLookup !== 'object') return [];
        // Every SHA-256 / MD5 of the group: hash rows and file facts alike.
        return CentralboxLookup.targets(group.entries);
    }

    function statusNodeFor(hash) {
        return bodyEl ? Array.from(bodyEl.querySelectorAll('.cinfo-lookup-status'))
            .find((node) => node.dataset.hash === hash) || null : null;
    }

    async function runLookup(kind, target) {
        const urls = (state.lookup && state.lookup.urls) || {};
        const key = target.hash;
        const current = state;
        current.busy[key] = true;
        const progress = (message) => {
            current.messages[key] = message;
            const node = state === current ? statusNodeFor(key) : null;
            if (node) node.textContent = message;
        };
        render();
        let result = { message: 'lookup failed', refresh: false };
        try {
            result = kind === 'fresh'
                ? await CentralboxLookup.fresh(target, urls, progress)
                : await CentralboxLookup.check(target, urls, progress);
        } catch (error) {
            // shown as "lookup failed"
        }
        current.busy[key] = false;
        current.messages[key] = result.message;
        if (result.refresh && typeof current.refresh === 'function') {
            try {
                await current.refresh();
            } catch (error) {
                // the box keeps what it shows
            }
        }
        if (state === current) render();
    }

    function renderHashes(parent, group) {
        const hashes = collectHashes(group);
        if (!hashes.length) return;
        const targets = lookupTargets(group);
        const urls = (state.lookup && state.lookup.urls) || {};
        const list = section(parent, 'hashes');
        hashes.forEach((item) => {
            const li = row('cinfo-hash');
            if (item.centralbox && item.centralbox.verdict === 'malicious') li.classList.add('cinfo-sev-b');
            const top = el('div', 'cinfo-hash-line');
            top.appendChild(el('span', 'cinfo-key', item.kind));
            top.appendChild(el('code', 'cinfo-hash-value', item.hash));
            const copy = el('button', 'cinfo-action', 'copy');
            copy.type = 'button';
            copy.addEventListener('click', () => Fenris.copyWithFeedback(item.hash, copy));
            const vt = el('a', 'cinfo-action', 'VirusTotal');
            vt.href = VT_FILE_URL + item.hash;
            vt.target = '_blank';
            vt.rel = 'noopener noreferrer';
            top.append(copy, vt);
            li.appendChild(top);

            const result = centralboxText(item.centralbox);
            const detection = item.entries.map((entry) => str(entry.detection)).find(Boolean);
            if (result || detection) {
                const info = el('div', 'cinfo-hash-info');
                if (detection) info.appendChild(el('span', sevClass(item.entries.find((entry) => entry.detection).severity), detection));
                if (result) {
                    const verdict = item.centralbox && item.centralbox.verdict;
                    info.appendChild(el('span', verdict === 'malicious' ? 'cinfo-sev-b' : verdict === 'suspicious' ? 'cinfo-sev-w' : verdict === 'clean' ? 'cinfo-sev-c' : 'cinfo-muted', result));
                }
                const report = item.centralbox && str(item.centralbox.report_url);
                if (report && Format().REPORT_URL_RE.test(report)) {
                    const link = el('a', 'cinfo-action', 'centralbox report');
                    link.href = report;
                    link.target = '_blank';
                    link.rel = 'noopener noreferrer';
                    info.appendChild(link);
                }
                li.appendChild(info);
            }

            const target = targets.find((candidate) => candidate.hash === item.hash);
            if (target) {
                const actions = el('div', 'cinfo-hash-lookup');
                const status = el('span', 'cinfo-lookup-status', state.messages[item.hash] || '');
                status.dataset.hash = item.hash;
                status.setAttribute('role', 'status');
                status.setAttribute('aria-live', 'polite');
                const busy = Boolean(state.busy[item.hash]);
                if (urls.check) {
                    const check = el('button', 'cinfo-action', 'check on centralbox');
                    check.type = 'button';
                    check.disabled = busy;
                    check.addEventListener('click', () => runLookup('check', target));
                    actions.appendChild(check);
                }
                if (urls.fresh && urls.freshStatus) {
                    const fresh = el('button', 'cinfo-action', 'run fresh lookup');
                    fresh.type = 'button';
                    fresh.disabled = busy;
                    fresh.addEventListener('click', () => runLookup('fresh', target));
                    actions.appendChild(fresh);
                }
                actions.appendChild(status);
                li.appendChild(actions);
            } else if (state.messages[item.hash]) {
                li.appendChild(el('div', 'cinfo-lookup-status', state.messages[item.hash]));
            }

            const sources = el('div', 'cinfo-sources');
            const seen = new Set();
            item.entries.forEach((entry) => {
                const key = `${entry.upload_id}:${entry.anchor_line_no || entry.line_no}`;
                if (seen.has(key)) return;
                seen.add(key);
                sources.appendChild(sourceNode(entry));
            });
            li.appendChild(sources);
            list.appendChild(li);
        });
    }

    // ------------------------------------------------------------------
    // File facts, findings, activity
    // ------------------------------------------------------------------

    function renderFacts(parent, group) {
        const infos = group.entries.filter((entry) => entry.kind === 'file_info'
            && FACTS.some(([key]) => str(entry[key])));
        if (!infos.length) return;
        const list = section(parent, 'file');
        infos.forEach((entry) => {
            const li = row('cinfo-facts');
            if (str(entry.path)) li.appendChild(tokenized('div', 'cinfo-path', entry.path));
            const grid = el('dl', 'cinfo-grid');
            FACTS.forEach(([key, label]) => {
                const value = str(entry[key]);
                if (!value) return;
                grid.appendChild(el('dt', '', label));
                const dd = el('dd');
                let cls = '';
                if (key === 'signature') cls = sevClass(SIGNATURE_SEVERITY[value.split(' ')[0]] || '');
                if (key === 'signed' && value === 'not signed') cls = 'cinfo-sev-w';
                if (key === 'company') cls = 'hl-company';
                dd.appendChild(el('span', cls, value));
                // VirusTotal Intelligence: the files signed with this certificate.
                const signed = key === 'thumbprint' ? Fenris.virusTotal.thumbprint(value) : '';
                if (signed) dd.append(' ', lookupLink(signed, 'VirusTotal', 'files signed with this certificate'));
                if (key === 'original_name' && entry.original_name_differs) {
                    dd.appendChild(el('span', 'cinfo-note cinfo-sev-w', ' differs from the file name'));
                }
                grid.appendChild(dd);
            });
            li.appendChild(grid);
            li.appendChild(sourceNode(entry));
            list.appendChild(li);
        });
    }

    function renderFindings(parent, group) {
        // Hash rows with a detection, and file facts a hash row was merged into.
        const findings = group.entries.filter((entry) => entry.kind === 'detection' || entry.kind === 'fixlog'
            || ((entry.kind === 'hash' || entry.kind === 'file_info') && str(entry.detection)));
        if (!findings.length) return;
        const list = section(parent, 'detections and results');
        findingGroups(findings).forEach((entries) => {
            const first = entries[0];
            const li = row();
            const line = el('div', 'cinfo-finding');
            if (first.kind === 'fixlog') {
                line.appendChild(el('span', 'cinfo-key', 'fixlist'));
                line.appendChild(el('span', '', str(first.result) || 'fixlist result'));
            } else {
                line.appendChild(el('span', 'cinfo-key', first.source === 'defender' ? 'Defender' : 'detection'));
                line.appendChild(el('span', sevClass(first.severity), str(first.detection) || 'detection'));
                const actions = [...new Set(entries.map((entry) => str(entry.action)).filter(Boolean))];
                if (actions.length) line.appendChild(el('span', 'cinfo-muted', actions.join(', ')));
                if (first.in_folder) line.appendChild(el('span', 'cinfo-note', 'the folder was detected'));
            }
            li.appendChild(line);
            // One source label, then a link per line ("this log L5130 L5134 ...").
            const source = sourceLabel(el('span', 'cinfo-src'), first);
            const linked = new Set();
            entries.forEach((entry) => {
                // Lines that jump to the same line (their anchor) get one link.
                const target = Number(entry.anchor_line_no || entry.line_no) || 0;
                if (linked.has(target)) return;
                linked.add(target);
                const link = lineLink(entry);
                if (link) source.appendChild(link);
            });
            li.appendChild(source);
            list.appendChild(li);
        });
    }

    // Findings that say the same in the same log share one row: the same
    // detection (or fixlist result) on several lines, e.g. one Defender
    // threat detected and removed again and again. Its lines in log order,
    // each once; the actions of all of them.
    function findingGroups(findings) {
        const groups = new Map();
        const lines = new Set();
        findings.forEach((entry) => {
            const lineKey = `${entry.upload_id}:${entry.line_no}:${entry.kind}`;
            if (lines.has(lineKey)) return;
            lines.add(lineKey);
            const key = JSON.stringify([str(entry.upload_id), str(entry.log_type), str(entry.system), str(entry.kind),
                str(entry.source), str(entry.detection), str(entry.severity), Boolean(entry.in_folder),
                entry.kind === 'fixlog' ? str(entry.result) : '']);
            if (!groups.has(key)) groups.set(key, []);
            groups.get(key).push(entry);
        });
        const lineNo = (entry) => Number(entry.anchor_line_no || entry.line_no) || 0;
        return [...groups.values()].map((entries) => entries.slice().sort((a, b) => lineNo(a) - lineNo(b)));
    }

    // The FRST / Addition lines that point at the shown line (reverse
    // entries). Lines of the same log that point here the same way share one
    // row and one box: per line its link, rule verdict and text.
    function reverseGroups(items) {
        const groups = new Map();
        items.forEach((entry) => {
            const key = JSON.stringify([str(entry.upload_id), str(entry.log_type), str(entry.system),
                str(entry.what), str(entry.match), Boolean(entry.in_folder)]);
            if (!groups.has(key)) groups.set(key, []);
            groups.get(key).push(entry);
        });
        // In log order within a box.
        const lineNo = (entry) => Number(entry.anchor_line_no || entry.line_no) || 0;
        return [...groups.values()].map((entries) => entries.slice().sort((a, b) => lineNo(a) - lineNo(b)));
    }

    function renderReverse(parent, group) {
        const items = group.entries.filter((entry) => entry.kind === 'reverse');
        if (!items.length) return;
        const list = section(parent, 'FRST / Addition lines');
        reverseGroups(items).forEach((entries) => {
            const first = entries[0];
            const li = row('cinfo-reverse');
            const head = el('div', 'cinfo-finding');
            if (str(first.what)) head.appendChild(el('span', 'cinfo-key', 'via ' + first.what));
            const how = Format().MATCH_NOTES[first.match];
            if (how) head.appendChild(el('span', 'cinfo-note', how));
            if (first.in_folder) head.appendChild(el('span', 'cinfo-note', 'in this folder'));
            if (head.childNodes.length) li.appendChild(head);
            const paint = statusPaint(worstStatus(entries.map((entry) => str(entry.line_status))));
            const box = el('div', 'cinfo-lines' + (paint ? ' cinfo-edge-' + paint : ''));
            entries.forEach((entry) => {
                const line = el('div', 'cinfo-lines-row');
                const gutter = el('span', 'cinfo-lines-no');
                const link = lineLink(entry);
                if (link) gutter.appendChild(link);
                line.appendChild(gutter);
                line.appendChild(statusLetter(str(entry.line_status)) || el('span', 'cinfo-status-letter'));
                line.appendChild(tokenized('span', 'cinfo-line-text', entry.text, true));
                box.appendChild(line);
            });
            li.appendChild(box);
            li.appendChild(sourceLabel(el('span', 'cinfo-src'), first));
            list.appendChild(li);
        });
    }

    // Spor flag tiers (spor_log.QUIET_FLAGS, HINT_FLAGS, MALWARE_FLAGS): normal
    // on many PCs grey, hints in the info colour, a known malware family
    // (Autodetect) malware, every other flag a warning.
    const QUIET_FLAGS = new Set(['!lolbin']);
    // Hints and Spor 0.8.1 context flags (spor_log.INFO_FLAGS): the info colour, never a warning.
    const HINT_FLAGS = new Set(['!renamed-program', '!abused-tld', '!remote-access', '!account-change', '!history-deleted',
        '!disk-image', '!upload', '!new-service', '!task-deleted', '!startup-item', '!drop-group']);
    const MALWARE_FLAGS = new Set(['!known-malware']);

    function flagClass(flag) {
        if (QUIET_FLAGS.has(flag)) return 'cinfo-flag cinfo-sev-g';
        if (HINT_FLAGS.has(flag)) return 'cinfo-flag cinfo-sev-i';
        if (MALWARE_FLAGS.has(flag)) return 'cinfo-flag cinfo-sev-b';
        return 'cinfo-flag cinfo-sev-w';
    }

    function flagsNode(flags) {
        const wrap = el('span', 'cinfo-flags');
        (Array.isArray(flags) ? flags : []).filter((flag) => typeof flag === 'string').forEach((flag) => {
            wrap.appendChild(el('span', flagClass(flag), flag));
        });
        return wrap;
    }

    const DOWNLOAD_KEYS = new Set(['from', 'page', 'referrer']);

    // A lookup action link (VirusTotal, who.is, ...), opened in a new tab without a handle on this page.
    function lookupLink(href, text, title = '') {
        const link = el('a', 'cinfo-action', text);
        link.href = href;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        if (title) link.title = title;
        return link;
    }

    function extraNode(extra) {
        const list = el('dl', 'cinfo-grid cinfo-extra');
        (Array.isArray(extra) ? extra : []).forEach((pair) => {
            if (!Array.isArray(pair) || pair.length < 2) return;
            list.appendChild(el('dt', '', str(pair[0])));
            const dd = el('dd');
            const value = str(pair[1]);
            // Only VirusTotal addresses become links; any other URL in a log
            // could point anywhere, so it stays text.
            if (VT_URL_RE.test(value)) {
                const link = el('a', 'cinfo-link', value);
                link.href = value;
                link.target = '_blank';
                link.rel = 'noopener noreferrer';
                dd.appendChild(link);
            } else {
                appendTokens(dd, value);
                // A download's address (Spor "from" / "page" / "referrer"): looked
                // up like a URL in the analyzer and on the log page (Fenris.lookups.url),
                // never opened itself.
                const url = DOWNLOAD_KEYS.has(str(pair[0])) ? Fenris.lookupUrl(value) : null;
                if (url && url.value) {
                    Fenris.lookupLinks('url', url.value).forEach((link) => {
                        dd.append(' ', lookupLink(link.href, link.label, link.detail));
                    });
                }
            }
            list.appendChild(dd);
        });
        return list.childNodes.length ? list : null;
    }

    // A line's text without the time it starts with ("2026-11-01 10:41:24
    // [Persistence] service installed: X" -> "[Persistence] service installed: X").
    const LEADING_TIME_RE = /^\d{4}-\d\d-\d\d \d\d:\d\d(?::\d\d)? +/;

    // Activity rows that say the same in the same log share one row: a
    // service installed again and again, one Defender threat detected many
    // times, the same SUMMARY finding repeated. Same kind, section, tags,
    // role, match, status, flags, extra and text (its time left out); in
    // time order within a group, the groups newest first (no time last).
    function activityGroups(items) {
        const time = Format().entryTime;
        const groups = new Map();
        items.forEach((entry) => {
            const text = entry.kind === 'evidence' ? str(entry.details) : str(entry.text).replace(LEADING_TIME_RE, '');
            const flags = (Array.isArray(entry.flags) ? entry.flags : []).filter((flag) => typeof flag === 'string').sort();
            const key = JSON.stringify([str(entry.upload_id), str(entry.log_type), str(entry.system), str(entry.kind),
                entry.kind === 'evidence' ? str(entry.sources) : Format().mentionWhere(entry), str(entry.tags),
                entry.kind === 'mention' ? Format().mentionRole(entry) : '', str(entry.match), Boolean(entry.in_folder),
                str(entry.file_status), str(entry.severity), flags, text, Array.isArray(entry.extra) ? entry.extra : []]);
            if (!groups.has(key)) groups.set(key, []);
            groups.get(key).push(entry);
        });
        const byTime = (a, b) => time(a).localeCompare(time(b)) || (Number(a.line_no) || 0) - (Number(b.line_no) || 0);
        const newest = (entries) => entries.reduce((last, entry) => (time(entry) > last ? time(entry) : last), '');
        return [...groups.values()]
            .map((entries) => entries.slice().sort(byTime))
            .sort((a, b) => {
                const ta = newest(a);
                const tb = newest(b);
                if (Boolean(ta) !== Boolean(tb)) return ta ? -1 : 1;
                return tb.localeCompare(ta);
            });
    }

    // How many line links a grouped row shows before "+N more".
    const GROUP_LINKS = 12;

    // One source label, then a link per line of the group (each target once);
    // past GROUP_LINKS a button shows the rest.
    function groupSourceNode(entries) {
        const wrap = sourceLabel(el('span', 'cinfo-src'), entries[0]);
        const seen = new Set();
        const links = [];
        entries.forEach((entry) => {
            const target = `${str(entry.upload_id)}:${Number(entry.anchor_line_no || entry.line_no) || 0}`;
            if (seen.has(target)) return;
            seen.add(target);
            const link = lineLink(entry);
            if (link) links.push(link);
        });
        links.slice(0, GROUP_LINKS).forEach((link) => wrap.appendChild(link));
        const rest = links.slice(GROUP_LINKS);
        if (rest.length) {
            const more = el('button', 'cinfo-link cinfo-more', `+${rest.length} more`);
            more.type = 'button';
            more.title = 'show the links to all lines';
            more.addEventListener('click', () => {
                more.replaceWith(...rest);
            });
            wrap.appendChild(more);
        }
        return wrap;
    }

    function renderActivity(parent, group) {
        const items = group.entries.filter((entry) => entry.kind === 'evidence' || entry.kind === 'mention');
        if (!items.length) return;
        const time = Format().entryTime;
        const list = section(parent, 'activity');
        activityGroups(items).forEach((entries) => {
            // The newest line speaks for the group (its text, status and extra are the group's).
            const entry = entries[entries.length - 1];
            const li = row(sevClass(entry.severity) ? 'cinfo-flagged' : '');
            const head = el('div', 'cinfo-activity-head');
            const times = entries.map(time).filter(Boolean);
            if (times.length > 1 && times[0].slice(0, 16) !== times[times.length - 1].slice(0, 16)) {
                head.appendChild(el('span', 'cinfo-time', `${times[0].slice(0, 16)} … ${times[times.length - 1].slice(0, 16)}`));
            } else if (time(entry)) {
                head.appendChild(el('span', 'cinfo-time', time(entry).slice(0, 16)));
            }
            if (entries.length > 1) {
                const count = el('span', 'cinfo-count', `${entries.length}×`);
                count.title = `${entries.length} lines say this`;
                head.appendChild(count);
            }
            if (entry.kind === 'evidence') {
                head.appendChild(el('span', 'cinfo-key', 'timeline'));
                if (str(entry.sources)) head.appendChild(el('span', 'cinfo-tags', '[' + entry.sources + ']'));
            } else {
                head.appendChild(el('span', 'cinfo-key', Format().mentionWhere(entry) || 'log'));
                if (str(entry.tags)) head.appendChild(el('span', 'cinfo-tags', '[' + entry.tags + ']'));
            }
            const role = entry.kind === 'mention' ? Format().mentionRole(entry) : '';
            if (role) head.appendChild(el('span', 'cinfo-role', role));
            if (str(entry.file_status)) {
                const status = entry.file_status;
                const cls = status === 'unsigned' || status === 'no access' ? 'cinfo-sev-w'
                    : /signature$/.test(status) ? 'cinfo-sev-b' : 'cinfo-muted';
                head.appendChild(el('span', 'cinfo-status ' + cls, '[' + status + ']'));
            }
            head.appendChild(flagsNode(entry.flags));
            li.appendChild(head);
            let detail = entry.kind === 'evidence' ? str(entry.details) : str(entry.text);
            // A group's lines differ in their time only: the head shows it.
            if (entries.length > 1 && entry.kind !== 'evidence') detail = detail.replace(LEADING_TIME_RE, '');
            if (detail) li.appendChild(tokenized('div', 'cinfo-text', detail));
            const extra = extraNode(entry.extra);
            if (extra) li.appendChild(extra);
            li.appendChild(entries.length > 1 ? groupSourceNode(entries) : sourceNode(entry));
            list.appendChild(li);
        });
    }

    // ------------------------------------------------------------------
    // The whole box
    // ------------------------------------------------------------------

    function render() {
        if (!state || !bodyEl) return;
        const list = entries();
        const scrollTop = bodyEl.scrollTop;
        bodyEl.innerHTML = '';
        // A Spor log's own lines (correlations/spor_self.py): no other log involved.
        const ownLines = list.length > 0 && list.every((entry) => isOwn(entry) && str(entry.log_type) !== 'Addition');
        if (titleEl) titleEl.textContent = ownLines ? 'what other lines of this log say about this line' : 'what other logs say about this line';
        const intro = el('div', 'cinfo-intro');
        if (str(state.lineText)) intro.appendChild(lineNode(state.lineText, state.lineStatus, state.lineIsFrst !== false));
        const summary = el('p', 'cinfo-summary');
        summary.appendChild(document.createTextNode(Format().header(list, isOwn, { scope: state.scope, name: state.name })));
        const letter = str(state.status);
        const cls = Format().STATUS_CLASS[letter];
        if (cls) {
            summary.appendChild(document.createTextNode(' - worst finding: '));
            summary.appendChild(el('span', 'cinfo-status-letter cinfo-sev-' + cls, letter));
        }
        intro.appendChild(summary);
        bodyEl.appendChild(intro);
        if (!list.length) {
            // emptyText may change while the box is open ("loading...").
            const empty = typeof state.emptyText === 'function' ? state.emptyText() : state.emptyText;
            bodyEl.appendChild(el('p', 'cinfo-empty', str(empty) || 'the other logs say nothing about this line (anymore)'));
            return;
        }
        Format().fileGroups(list).forEach((group) => {
            const box = el('section', 'cinfo-file');
            const heading = el('h3', 'cinfo-file-title');
            heading.appendChild(group.file ? tokenized('span', 'cinfo-file-name', group.file)
                : el('span', 'cinfo-file-name', 'this line'));
            if (group.how === 'folder') heading.appendChild(el('span', 'cinfo-note', 'a folder this file is in'));
            else if (group.how === 'reverse') heading.appendChild(el('span', 'cinfo-note', 'pointed at by'));
            else if (group.how) heading.appendChild(el('span', 'cinfo-note', group.how));
            // Where the related file is (a detected sibling, a copy, a file of the same name).
            if (group.otherPath && group.how) heading.appendChild(el('span', 'cinfo-muted', group.otherPath));
            box.appendChild(heading);
            const changed = Format().fileChanges(group, state.lineText, isOwn);
            if (changed) box.appendChild(el('p', 'cinfo-changed', changed));
            renderHashes(box, group);
            renderFindings(box, group);
            renderFacts(box, group);
            renderActivity(box, group);
            renderReverse(box, group);
            bodyEl.appendChild(box);
        });
        bodyEl.scrollTop = scrollTop;
    }

    return { open, close, isOpen, render };
})();
