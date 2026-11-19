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
 *     getEntries(),        the line's entries now (called again after a lookup)
 *     isOwn(entry),        an entry of the shown log itself
 *     scope, name,         'case' / 'user' and the forum user (header text)
 *     status,              the line's correlation status letter ('' for none)
 *     onJump(lineNo, entry), go to a line of the shown log (own entries)
 *     lookup: {canLookup, urls: {check, fresh, freshStatus}},
 *     refresh(),           fetch the correlations again (after a lookup)
 *     trigger,             focus returns here when the box closes
 * })
 * Needs correlation_format.js; centralbox_lookup.js for the lookups. */
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

    function sourceNode(entry) {
        const wrap = el('span', 'cinfo-src');
        const own = isOwn(entry);
        wrap.appendChild(el('span', 'cinfo-src-type', own ? 'this log' : str(entry.log_type) || 'log'));
        if (!own && entry.system === 'different') wrap.appendChild(el('span', 'cinfo-src-other', 'other system?'));
        const lineNo = Number(entry.anchor_line_no || entry.line_no);
        const label = Number.isInteger(lineNo) && lineNo > 0 ? 'L' + lineNo : 'open';
        if (own) {
            const jump = el('button', 'cinfo-link cinfo-jump', label);
            jump.type = 'button';
            jump.title = 'go to the line in this log';
            jump.addEventListener('click', () => {
                const onJump = state && state.onJump;
                close();
                if (typeof onJump === 'function') onJump(lineNo, entry);
            });
            wrap.appendChild(jump);
        } else {
            const url = Format().logUrl(entry);
            if (url) {
                const link = el('a', 'cinfo-link', label);
                link.href = url;
                link.target = '_blank';
                link.rel = 'noopener noreferrer';
                link.title = `open the ${str(entry.log_type) || 'log'} at this line`;
                wrap.appendChild(link);
            }
        }
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
        return CentralboxLookup.targets(group.entries.filter((entry) => entry.kind === 'hash'));
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
            if (str(entry.path)) li.appendChild(el('div', 'cinfo-path', entry.path));
            const grid = el('dl', 'cinfo-grid');
            FACTS.forEach(([key, label]) => {
                const value = str(entry[key]);
                if (!value) return;
                grid.appendChild(el('dt', '', label));
                const dd = el('dd');
                let cls = '';
                if (key === 'signature') cls = sevClass(SIGNATURE_SEVERITY[value.split(' ')[0]] || '');
                if (key === 'signed' && value === 'not signed') cls = 'cinfo-sev-w';
                dd.appendChild(el('span', cls, value));
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
        const findings = group.entries.filter((entry) => entry.kind === 'detection' || entry.kind === 'fixlog'
            || (entry.kind === 'hash' && str(entry.detection)));
        if (!findings.length) return;
        const list = section(parent, 'detections and results');
        const seen = new Set();
        findings.forEach((entry) => {
            const key = `${entry.upload_id}:${entry.line_no}:${entry.kind}`;
            if (seen.has(key)) return;
            seen.add(key);
            const li = row();
            const line = el('div', 'cinfo-finding');
            if (entry.kind === 'fixlog') {
                line.appendChild(el('span', 'cinfo-key', 'fixlist'));
                line.appendChild(el('span', '', str(entry.result) || 'fixlist result'));
            } else {
                line.appendChild(el('span', 'cinfo-key', entry.source === 'defender' ? 'Defender' : 'detection'));
                line.appendChild(el('span', sevClass(entry.severity), str(entry.detection) || 'detection'));
                if (str(entry.action)) line.appendChild(el('span', 'cinfo-muted', str(entry.action)));
                if (entry.in_folder) line.appendChild(el('span', 'cinfo-note', 'the folder was detected'));
            }
            li.appendChild(line);
            li.appendChild(sourceNode(entry));
            list.appendChild(li);
        });
    }

    function flagsNode(flags) {
        const wrap = el('span', 'cinfo-flags');
        (Array.isArray(flags) ? flags : []).filter((flag) => typeof flag === 'string').forEach((flag) => {
            wrap.appendChild(el('span', flag === '!lolbin' ? 'cinfo-flag cinfo-sev-g' : 'cinfo-flag cinfo-sev-w', flag));
        });
        return wrap;
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
                dd.textContent = value;
            }
            list.appendChild(dd);
        });
        return list.childNodes.length ? list : null;
    }

    function renderActivity(parent, group) {
        const items = group.entries.filter((entry) => entry.kind === 'evidence' || entry.kind === 'mention');
        if (!items.length) return;
        const time = Format().entryTime;
        // Newest first; entries without a time last.
        items.sort((a, b) => {
            const ta = time(a);
            const tb = time(b);
            if (Boolean(ta) !== Boolean(tb)) return ta ? -1 : 1;
            return tb.localeCompare(ta);
        });
        const list = section(parent, 'activity');
        items.forEach((entry) => {
            const li = row(sevClass(entry.severity) ? 'cinfo-flagged' : '');
            const head = el('div', 'cinfo-activity-head');
            if (time(entry)) head.appendChild(el('span', 'cinfo-time', time(entry).slice(0, 16)));
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
            const detail = entry.kind === 'evidence' ? str(entry.details) : str(entry.text);
            if (detail) li.appendChild(el('div', 'cinfo-text', detail));
            const extra = extraNode(entry.extra);
            if (extra) li.appendChild(extra);
            li.appendChild(sourceNode(entry));
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
        const intro = el('div', 'cinfo-intro');
        if (str(state.lineText)) intro.appendChild(el('pre', 'cinfo-line', state.lineText));
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
            bodyEl.appendChild(el('p', 'cinfo-empty', 'the other logs say nothing about this line (anymore)'));
            return;
        }
        Format().fileGroups(list).forEach((group) => {
            const box = el('section', 'cinfo-file');
            const heading = el('h3', 'cinfo-file-title');
            heading.appendChild(el('span', 'cinfo-file-name', group.file || 'this line'));
            if (group.how === 'folder') heading.appendChild(el('span', 'cinfo-note', 'a folder this file is in'));
            else if (group.how) heading.appendChild(el('span', 'cinfo-note', group.how));
            box.appendChild(heading);
            const changed = Format().fileChanges(group, state.lineText, isOwn);
            if (changed) box.appendChild(el('p', 'cinfo-changed', changed));
            renderHashes(box, group);
            renderFindings(box, group);
            renderFacts(box, group);
            renderActivity(box, group);
            bodyEl.appendChild(box);
        });
        bodyEl.scrollTop = scrollTop;
    }

    return { open, close, isOpen, render };
})();
