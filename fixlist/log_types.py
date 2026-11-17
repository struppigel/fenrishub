"""Names of the built-in log types and the groups they fall into.

A leaf module (no app imports) so models, the analyzer, the highlighters and
the views can all share these without import cycles. Log types beyond these
come from LogTypeDetectionRule rows.
"""

LOG_TYPE_UNKNOWN = 'Unknown'
LOG_TYPE_FRST = 'FRST'
LOG_TYPE_ADDITION = 'Addition'
LOG_TYPE_FRST_AND_ADDITION = 'FRST&Addition'

# Logs the analyzer classifies line by line (and keeps cached analyses of).
ANALYZED_LOG_TYPES = (LOG_TYPE_FRST, LOG_TYPE_ADDITION, LOG_TYPE_FRST_AND_ADDITION)
# Logs that carry an Addition.txt part.
ADDITION_LOG_TYPES = (LOG_TYPE_ADDITION, LOG_TYPE_FRST_AND_ADDITION)
# Scanner logs that list detections.
DETECTION_LOG_TYPES = ('ESET', 'Emsisoft', 'AdwCleaner', 'Malwarebytes', 'HitmanPro', 'Trojan Killer')
