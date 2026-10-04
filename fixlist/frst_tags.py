"""The tags FRST writes in square brackets after a file's company, e.g.

    (Company) [File not signed] [File is in use] C:\\path\\file.exe

FRST writes them in the language of the scanned system. To support another
language, add its wording (without the brackets) to the matching tuple below.
The extractors in frst_extractors.py build their patterns from these tuples, so
no regex needs to change. Order does not matter.

Saved rules store the fields parsed from their line. After adding a language,
re-parse them (`python manage.py reparse_rules --apply`, or the admin action
"Re-parse selected rules from source_text") so rules from such lines match.
"""

# The file has no valid digital signature. Sets FrstEntry.file_not_signed.
NOT_SIGNED = (
    "File not signed",            # English
    "Archivo no firmado",         # Spanish
    "Arquivo não assinado",       # Portuguese
    "Bestand niet getekend",      # Dutch
    "Brak podpisu cyfrowego",     # Polish
    "Datei ist nicht signiert",   # German
    "Fichier non signé",          # French
    "Файл не подписан",           # Russian
    "文件未签名",                  # Chinese
)

# FRST could not tell whether the file is signed (e.g. access denied).
# Recognized as a tag, but does not set file_not_signed.
SIGNATURE_UNKNOWN = (
    "File not signed?",           # English
    "Archivo no firmado?",        # Spanish
)

# The file was locked by another process when FRST read it.
IN_USE = (
    "File is in use",                    # English
    "El archivo está en uso",            # Spanish
    "Fichier en cours d'utilisation",    # French
    "Datei wird verwendet",              # German
    "文件正在使用中",                      # Chinese
)

# Tags that carry a value after a fixed beginning, e.g. `[symlink -> C:\target.dll]`.
PREFIXED = (
    "symlink -> ",
)

ALL_FIXED = NOT_SIGNED + SIGNATURE_UNKNOWN + IN_USE
