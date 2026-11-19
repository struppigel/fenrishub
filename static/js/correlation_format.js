/* How case correlations (fixlist/case_correlations.py) are described: the text
 * of a finding, where it comes from, the menu header, links to the related log
 * and centralbox reports. Shared by the analyzer (log_analyzer/case_correlations.js)
 * and the uploaded log page, so both say the same thing about the same entry.
 * Pure functions; `isOwn(entry)` tells an entry of the shown log itself apart. */
window.CorrelationFormat = (function () {
    const DOT = ' · ';

    // How an entry was matched when not through the line's own file
    // (case_correlations.MATCH_NOTES).
    const MATCH_NOTES = {
        argument: 'file in command line',
        registry: 'same registry value',
        service: 'same service',
        task: 'same task',
        extension: 'same extension',
        clsid: 'same CLSID',
        firewall: 'same firewall rule',
        uninstall: 'same installed program',
        msi: 'same installed program',
    };

    // Line-verdict status letter -> the marker / icon colour class.
    const STATUS_CLASS = { B: 'b', P: 'p', C: 'c', A: 'a', '!': 'w', G: 'g', S: 's', I: 'i', J: 'j' };

    const REPORT_URL_RE = /^https:\/\/centralbox\.dev\/analysis\/[0-9a-f]{64}$/;

    function sha256Of(entry) {
        return typeof entry.sha256 === 'string' && /^[0-9a-f]{64}$/.test(entry.sha256) ? entry.sha256 : '';
    }

    function md5Of(entry) {
        return typeof entry.md5 === 'string' && /^[0-9a-f]{32}$/.test(entry.md5) ? entry.md5 : '';
    }

    // A hash entry's hash as text ('SHA-256 …', else 'MD5 …'), '' otherwise.
    function hashText(entry) {
        if (entry.kind !== 'hash') return '';
        const sha = sha256Of(entry);
        const md5 = md5Of(entry);
        return sha ? 'SHA-256 ' + sha : md5 ? 'MD5 ' + md5 : '';
    }

    // A Spor timeline entry (case_correlations.evidence_text has the short
    // form): when and by which sources the file was seen, its status, Spor's
    // flags and the details ("downloaded from ...", "+3 more times since ...").
    function evidence(entry) {
        const text = (value) => (typeof value === 'string' ? value : '');
        const seen = [text(entry.time).slice(0, 16), text(entry.sources)].filter(Boolean).join(' ');
        const flags = Array.isArray(entry.flags) ? entry.flags.filter((flag) => typeof flag === 'string').join(' ') : '';
        return [text(entry.file), seen, text(entry.file_status), flags, text(entry.details)]
            .filter(Boolean).join(DOT) || 'seen in timeline';
    }

    function text(value) {
        return typeof value === 'string' ? value : '';
    }

    // Facts about the file itself (a Spor FILES / AMCACHE FILES line, an FRST
    // Search File: entry): signature, signer, version, company, size, ...
    function fileInfo(entry) {
        const original = text(entry.original_name);
        return [
            text(entry.file),
            entry.signature ? 'signature ' + text(entry.signature) : '',
            text(entry.signer),
            text(entry.company),
            entry.version ? 'version ' + text(entry.version) : '',
            original && entry.original_name_differs ? 'original name ' + original + ' (differs)' : '',
            text(entry.file_status),
            entry.signed ? text(entry.signed) : '',
        ].filter(Boolean).join(DOT) || 'file details';
    }

    // Where a log names the file: "PREFETCH › Files loaded ...", "loaded by
    // <program>", its status and flags.
    function mentionWhere(entry) {
        return [text(entry.section), text(entry.subsection)].filter(Boolean).join(' \u203a ');
    }

    function mentionRole(entry) {
        const parent = text(entry.parent);
        if (entry.role === 'loaded' && parent) return 'loaded by ' + parent;
        if (entry.role === 'registry' && parent) return 'in ' + parent;
        if (entry.role === 'target') return 'pointed at';
        if (entry.role === 'shortcut target') return 'shortcut target';
        if (entry.role === 'shortcut') return 'the shortcut itself';
        if (entry.role === 'uninstall entry') return 'installed program';
        if (entry.role === 'installer event') return 'Windows Installer';
        if (entry.role === 'package') return 'Store / MSIX package';
        if (entry.role === 'removed by MAU') return 'removed by MAU';
        if (entry.role === 'dll' && parent) return 'service DLL of ' + parent;
        if (entry.folder && entry.in_folder) return 'in this folder';
        return parent ? 'under ' + parent : '';
    }

    function mention(entry) {
        const flags = Array.isArray(entry.flags) ? entry.flags.filter((flag) => typeof flag === 'string').join(' ') : '';
        return [text(entry.file), mentionWhere(entry), mentionRole(entry), text(entry.file_status), flags,
            text(entry.time).slice(0, 16)].filter(Boolean).join(DOT) || 'mentioned';
    }

    // What a related log says, without log ids: the detection name or family
    // and the centralbox verdict (or the fixlist result).
    function finding(entry) {
        if (entry.kind === 'fixlog') return entry.result || 'fixlist result';
        if (entry.kind === 'evidence') return evidence(entry);
        if (entry.kind === 'file_info') return fileInfo(entry);
        if (entry.kind === 'mention') return mention(entry);
        const result = entry.centralbox && typeof entry.centralbox === 'object' ? entry.centralbox : null;
        // A bare hash (no detection, no centralbox result) shows the hash itself.
        const name = (result && (result.family || result.malware_type)) || entry.detection || hashText(entry);
        const verdict = result && result.verdict ? 'centralbox: ' + result.verdict
            : result && result.state === 'unknown' ? 'not in centralbox' : '';
        // A detection of a folder this line's file is in.
        const where = entry.in_folder ? (entry.kind === 'detection' ? 'in detected folder' : 'in this folder') : '';
        // A Windows Defender event (in a Fixlog, Addition or Spor log), not a scanner's detection.
        const source = entry.source === 'defender' ? 'Defender' : '';
        // Matched through something else than the line's own file.
        const how = MATCH_NOTES[entry.match] || '';
        // Which file the finding is about (the line's own, one in its command line, ...).
        const file = typeof entry.file === 'string' ? entry.file : '';
        return [file, name, verdict, source, how, where].filter(Boolean).join(DOT)
            || (entry.kind === 'hash' ? 'file hash' : 'detection');
    }

    // The log type a finding comes from, flagged when that log seems to come
    // from another system.
    function source(entry, isOwn) {
        if (isOwn(entry)) return 'this log';
        return String(entry.log_type || 'log') + (entry.system === 'different' ? DOT + 'other system?' : '');
    }

    // One row per distinct finding (same source and finding listed once).
    function rows(entries, isOwn) {
        const seen = new Set();
        return (Array.isArray(entries) ? entries : []).filter((entry) => {
            if (!entry || typeof entry !== 'object') return false;
            const key = source(entry, isOwn) + '\n' + finding(entry);
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });
    }

    // Where the line's findings come from: other logs, the log's own Addition
    // part, or both. `scope` 'user': the forum user's logs (no case of yours).
    function header(entries, isOwn, { scope, name }) {
        const list = Array.isArray(entries) ? entries : [];
        const own = list.some(isOwn);
        const others = list.some((entry) => !isOwn(entry));
        const where = scope === 'user'
            ? `other logs of user ${name} (no case of yours)`
            : 'other logs of this case';
        if (own && !others) return "same file in this log's Addition part";
        if (own) return `same file in this log's Addition part and in ${where}`;
        return `same file in ${where}`;
    }

    // That log at the entry's line, which its page scrolls to and marks. For a
    // hash: the file's entry (path line or detection header), not the hash line.
    function logUrl(entry) {
        const id = String(entry.upload_id || '');
        const line = Number(entry.anchor_line_no || entry.line_no);
        if (!/^[A-Za-z0-9_-]+$/.test(id)) return '';
        return `/uploads/${encodeURIComponent(id)}/` + (Number.isInteger(line) && line > 0 ? `#L${line}` : '');
    }

    // Distinct centralbox report URLs of the entries (stored verdicts of known hashes).
    function reportUrls(entries) {
        const urls = [];
        (Array.isArray(entries) ? entries : []).forEach((entry) => {
            const result = entry && entry.centralbox && typeof entry.centralbox === 'object' ? entry.centralbox : null;
            const url = result && typeof result.report_url === 'string' ? result.report_url : '';
            if (REPORT_URL_RE.test(url) && !urls.includes(url)) urls.push(url);
        });
        return urls;
    }

    // Distinct file hashes of the entries (SHA-256, else the MD5 alone) with
    // the file each belongs to: [{hash, file}].
    function hashValues(entries) {
        const hashes = [];
        (Array.isArray(entries) ? entries : []).forEach((entry) => {
            if (!entry || entry.kind !== 'hash') return;
            const hash = sha256Of(entry) || md5Of(entry);
            if (hash && !hashes.some((known) => known.hash === hash)) {
                hashes.push({ hash, file: typeof entry.file === 'string' ? entry.file : '' });
            }
        });
        return hashes;
    }

    // When an entry happened ('' if the log gives no time), for sorting.
    function entryTime(entry) {
        const value = entry && (entry.time || entry.modified || entry.created);
        return typeof value === 'string' ? value : '';
    }

    // The entries per file they are about, the line's own file(s) first, then
    // files in its command line / same registry value, then folders it is in:
    // [{file, how, entries}] (`how`: '' / a MATCH_NOTES text / 'folder').
    function fileGroups(entries) {
        const groups = new Map();
        (Array.isArray(entries) ? entries : []).forEach((entry) => {
            if (!entry || typeof entry !== 'object') return;
            const file = text(entry.file);
            const how = entry.in_folder ? 'folder' : (MATCH_NOTES[entry.match] || '');
            const key = how + '\n' + file.toLowerCase();
            if (!groups.has(key)) groups.set(key, { file, how, entries: [] });
            groups.get(key).entries.push(entry);
        });
        const rank = (group) => (group.how === '' ? 0 : group.how === 'folder' ? 2 : 1);
        return [...groups.values()].sort((a, b) => rank(a) - rank(b));
    }

    // The size an FRST line gives its file: "[123456 2026-11-17]" (most
    // sections) or " - 000123456 ____A " (created / modified files).
    const LINE_SIZE_RES = [/\[(\d{1,12}) \d{4}-\d\d-\d\d\]/, / - (\d{9,12}) [_A-Za-z]{5} /];

    function lineSize(lineText) {
        for (const re of LINE_SIZE_RES) {
            const m = re.exec(text(lineText));
            if (m) return m[1].replace(/^0+(?=\d)/, '');
        }
        return '';
    }

    // "this file changed between the logs: ..." when the logs of this system
    // disagree on the size, MD5 or SHA-256 of a file group's file (or the
    // line's own size differs). Not rated: files are updated all the time.
    // '' when they agree, for a folder group and without two values.
    function fileChanges(group, lineText, isOwn) {
        if (!group || group.how === 'folder') return '';
        const own = typeof isOwn === 'function' ? isOwn : () => false;
        const facts = { size: new Map(), modified: new Map(), md5: new Map(), sha256: new Map() };
        const note = (kind, value, where) => {
            let key = text(value).toLowerCase().replace(/^0+(?=\d)/, '');
            // Modified times to the minute: FRST Search has no seconds (both are local time).
            if (kind === 'modified') key = key.slice(0, 16);
            if (key && !facts[kind].has(key)) facts[kind].set(key, where);
        };
        (group.entries || []).forEach((entry) => {
            if (!entry || entry.in_folder || entry.system === 'different') return;
            if (entry.kind !== 'file_info' && entry.kind !== 'hash') return;
            const where = (own(entry) ? 'this log' : text(entry.log_type) || 'other log') + ' L' + entry.line_no;
            if (entry.kind === 'file_info') {
                note('size', entry.size, where);
                note('modified', entry.modified, where);
            }
            note('md5', entry.md5, where);
            note('sha256', entry.sha256, where);
        });
        if (group.how === '' && facts.size.size) note('size', lineSize(lineText), 'this line');
        const parts = [];
        [['size', 'size'], ['modified', 'modified'], ['md5', 'MD5'], ['sha256', 'SHA-256']].forEach(([kind, label]) => {
            if (facts[kind].size < 2) return;
            const hash = kind === 'md5' || kind === 'sha256';
            const values = [...facts[kind]].map(([value, where]) => (hash ? value.slice(0, 12) + '…' : value)
                + ' (' + where + ')');
            parts.push(label + ' ' + values.join(', '));
        });
        return parts.length ? 'this file changed between the logs: ' + parts.join('; ') : '';
    }

    return {
        DOT, MATCH_NOTES, STATUS_CLASS, REPORT_URL_RE,
        finding, source, rows, header, logUrl, reportUrls, hashValues,
        sha256Of, md5Of, mentionWhere, mentionRole, entryTime, fileGroups, lineSize, fileChanges,
    };
})();
