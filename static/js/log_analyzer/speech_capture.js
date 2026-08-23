// Capturing a marked passage of the response as a reusable speech.
//
// Good speeches are written in the middle of a real reply: you type a paragraph
// and realise you will want it again next case. Rather than send the analyst to
// the speeches page to paste it in, mark it, press +speech, name it, and it is
// stored and selected for the analyzer in one step.
//
// The button sits next to the speeches picker rather than on a right-click,
// deliberately: inside a textarea the native context menu carries paste and the
// spell-check suggestions, which are exactly what someone writing prose wants
// to keep.

// Remembered so the analyst does not re-tick it every capture; whether names
// should become placeholders is a habit, not a per-speech decision.
const SPEECH_CAPTURE_PLACEHOLDERS_KEY = 'fenrishub_speech_capture_placeholders';

// The text marked when the button was pressed. Stashed on mousedown rather than
// read at click time, the way the snippet menus stash the caret: by the click
// the textarea has lost focus and some browsers collapse the selection with it.
let capturedSpeechText = '';
let speechCaptureBusy = false;

function getMarkedResponseText() {
    const textarea = document.getElementById('responseText');
    if (!textarea) {
        return '';
    }
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    if (start === end) {
        return '';
    }
    return textarea.value.substring(start, end);
}

function setSpeechCaptureError(message) {
    const errorElement = document.getElementById('speechCaptureError');
    if (!errorElement) {
        return;
    }
    errorElement.textContent = message || '';
    errorElement.hidden = !message;
}

// Rebuilt on every open rather than rendered server-side, so a category
// invented during this session is offered back on the next capture.
function fillSpeechCaptureCategories() {
    const datalist = document.getElementById('speechCaptureCategoryList');
    if (!datalist) {
        return;
    }
    const speeches = (window.logAnalyzerConfig || {}).speeches || [];
    const categories = [...new Set(speeches.map((s) => s.category).filter(Boolean))].sort();
    datalist.innerHTML = '';
    categories.forEach((category) => {
        const option = document.createElement('option');
        option.value = category;
        datalist.appendChild(option);
    });
}

function readStoredPlaceholderPreference() {
    try {
        return localStorage.getItem(SPEECH_CAPTURE_PLACEHOLDERS_KEY) === '1';
    } catch (e) {
        return false;
    }
}

function storePlaceholderPreference(enabled) {
    try {
        localStorage.setItem(SPEECH_CAPTURE_PLACEHOLDERS_KEY, enabled ? '1' : '0');
    } catch (e) { /* quota or disabled storage */ }
}

function openSpeechCaptureModal(text) {
    const modal = document.getElementById('speechCaptureModal');
    if (!modal) {
        return;
    }

    const nameInput = document.getElementById('speechCaptureName');
    const categoryInput = document.getElementById('speechCaptureCategory');
    const contentInput = document.getElementById('speechCaptureContent');
    const sharedInput = document.getElementById('speechCaptureShared');
    const placeholdersInput = document.getElementById('speechCapturePlaceholders');

    setSpeechCaptureError('');
    fillSpeechCaptureCategories();

    if (nameInput) nameInput.value = '';
    if (categoryInput) categoryInput.value = 'generic';
    // Windows textareas report CRLF; speeches are stored with plain newlines,
    // the same normalisation the insert path does.
    if (contentInput) contentInput.value = String(text || '').replace(/\r\n/g, '\n');
    // Sharing is the norm: a speech worth keeping is usually worth handing to
    // the other helpers too, so this starts on and is opted out of.
    if (sharedInput) sharedInput.checked = true;
    if (placeholdersInput) placeholdersInput.checked = readStoredPlaceholderPreference();

    speechCaptureBusy = false;
    updateSpeechCaptureBusyState();

    modal.hidden = false;
    const responseTextarea = document.getElementById('responseText');
    if (window.handleAnalyzerModalOpen) {
        window.handleAnalyzerModalOpen('speechCaptureModal', { triggerElement: responseTextarea });
    }
    // The dialog itself takes focus first (shared modal helper), then the name
    // field, which is the one thing the analyst still has to supply.
    if (nameInput) {
        setTimeout(() => nameInput.focus(), 0);
    }
}

function closeSpeechCaptureModal(options = {}) {
    const modal = document.getElementById('speechCaptureModal');
    if (!modal || modal.hidden) {
        return;
    }
    modal.hidden = true;
    speechCaptureBusy = false;
    if (window.handleAnalyzerModalClose) {
        window.handleAnalyzerModalClose('speechCaptureModal', options);
    }
}

function updateSpeechCaptureBusyState() {
    const saveButton = document.getElementById('speechCaptureSaveButton');
    if (saveButton) {
        saveButton.disabled = speechCaptureBusy;
        saveButton.textContent = speechCaptureBusy ? 'saving...' : 'save speech';
    }
}

async function saveSpeechCapture() {
    if (speechCaptureBusy) {
        return;
    }

    const nameInput = document.getElementById('speechCaptureName');
    const categoryInput = document.getElementById('speechCaptureCategory');
    const contentInput = document.getElementById('speechCaptureContent');
    const sharedInput = document.getElementById('speechCaptureShared');
    const placeholdersInput = document.getElementById('speechCapturePlaceholders');

    const name = nameInput ? nameInput.value.trim() : '';
    if (!name) {
        setSpeechCaptureError('Speech name is required.');
        if (nameInput) nameInput.focus();
        return;
    }

    let content = contentInput ? contentInput.value : '';
    const usePlaceholders = Boolean(placeholdersInput && placeholdersInput.checked);
    storePlaceholderPreference(usePlaceholders);
    if (usePlaceholders && typeof reverseSpeechPlaceholders === 'function') {
        content = reverseSpeechPlaceholders(content);
    }

    const createUrl = (window.logAnalyzerConfig || {}).speechCreateUrl || '';
    if (!createUrl) {
        setSpeechCaptureError('Speech creation is unavailable.');
        return;
    }

    speechCaptureBusy = true;
    updateSpeechCaptureBusyState();
    setSpeechCaptureError('');

    try {
        const response = await fetch(createUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCookie('csrftoken'),
            },
            body: JSON.stringify({
                name,
                content,
                category: categoryInput ? categoryInput.value.trim() : '',
                is_shared: Boolean(sharedInput && sharedInput.checked),
            }),
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            // The modal stays open with the text intact. A duplicate name must
            // never cost the analyst the paragraph they just wrote.
            throw new Error(errorData.error || 'Failed to save the speech.');
        }

        const data = await response.json();
        const config = window.logAnalyzerConfig || {};
        if (data.speech) {
            if (!Array.isArray(config.speeches)) {
                config.speeches = [];
            }
            config.speeches.push(data.speech);
            if (window.reloadSpeechMenu) {
                window.reloadSpeechMenu();
            }
        }
        closeSpeechCaptureModal();
    } catch (error) {
        setSpeechCaptureError(error.message || 'Failed to save the speech.');
    } finally {
        speechCaptureBusy = false;
        updateSpeechCaptureBusyState();
    }
}

// Greyed out until something is marked, so the button explains its own
// precondition instead of failing with an error when pressed.
function refreshAddSpeechButtonState() {
    const button = document.getElementById('addSpeechButton');
    if (!button) {
        return;
    }
    const marked = getMarkedResponseText().trim();
    button.disabled = !marked;
    button.title = marked
        ? 'save the marked text as a reusable speech'
        : 'mark text in the response, then save it as a reusable speech';
}

function setupAddSpeechButton() {
    const button = document.getElementById('addSpeechButton');
    const textarea = document.getElementById('responseText');
    // Both are absent for guests, who have no speeches to add to.
    if (!button || !textarea) {
        return;
    }

    // 'select' covers marking with the mouse or Shift+arrows; the rest catch
    // the caret moves and edits that collapse a selection again.
    ['select', 'keyup', 'mouseup', 'input', 'focus'].forEach((eventName) => {
        textarea.addEventListener(eventName, refreshAddSpeechButtonState);
    });
    // Fires for programmatic selection changes too, which the events above miss.
    document.addEventListener('selectionchange', () => {
        if (document.activeElement === textarea) {
            refreshAddSpeechButtonState();
        }
    });

    button.addEventListener('mousedown', () => {
        capturedSpeechText = getMarkedResponseText();
    });

    button.addEventListener('click', () => {
        // Keyboard activation never fired mousedown, so fall back to reading the
        // selection now - it survives, because focus has not moved yet.
        const marked = capturedSpeechText || getMarkedResponseText();
        if (!marked.trim()) {
            return;
        }
        openSpeechCaptureModal(marked);
        capturedSpeechText = '';
    });

    refreshAddSpeechButtonState();
}
