"""Where a log's facts were found: the lines of each fact, and whether it is
a fact about the whole log.

Filled while the analyzer scans a log (fact rules, tag sources, whole-log
rules) and frozen before conditional rules read it. Lines are analyzed-line
indexes (the position in the payload's `lines`); the log page's line numbers
are only added for display. Pure, no app imports.
"""


class FactIndex:
    __slots__ = ('_lines', '_wholelog')

    def __init__(self):
        self._lines = {}        # fact id -> [index, ...] in scan order, no repeats
        self._wholelog = set()  # fact ids found by whole-log rules

    def add(self, fact_id, index=None):
        """Record `fact_id` on analyzed line `index`, or (None) for the whole log."""
        if index is None:
            self._wholelog.add(fact_id)
            return
        indexes = self._lines.setdefault(fact_id, [])
        if not indexes or indexes[-1] != index:
            indexes.append(index)

    def __bool__(self):
        return bool(self._lines or self._wholelog)

    def __contains__(self, fact_id):
        return fact_id in self._lines or fact_id in self._wholelog

    def fact_ids(self):
        return set(self._lines) | self._wholelog

    def lines_of(self, fact_id):
        return self._lines.get(fact_id, [])

    def payload(self, line_nos):
        """[{id, line_indexes, line_nos, wholelog}] by fact id. `line_nos[index]`
        is the log page line number of an analyzed line."""
        return [
            {
                'id': fact_id,
                'line_indexes': list(self._lines.get(fact_id, [])),
                'line_nos': [line_nos[index] for index in self._lines.get(fact_id, [])],
                'wholelog': fact_id in self._wholelog,
            }
            for fact_id in sorted(self.fact_ids())
        ]
