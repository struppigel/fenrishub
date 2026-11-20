"""Correlations: what the other logs of an infection case (and a Spor log's
own lines) say about the lines of a log.

- scope: which logs a log is correlated with, and whether they come from the
  same machine;
- entries: the entry shapes, matches, statuses and notes; folders: folders
  too broad to count;
- collector: the entries of one line, each source line once under its
  strongest match;
- sources / spor_source / defender: the index of what the related logs say,
  per log type (a Spor log is read once: spor_source.build);
- related: detected siblings, copies, files of the same name, files inside a
  folder; timing: lines and Spor events at the same time;
- forward: the correlations of an FRST / Addition log (computed, cached);
  reverse: the FRST / Addition lines pointing at another log's lines;
- spor_self: links between the lines of one Spor log.

fixlist/case_correlations.py re-exports the names the rest of the app uses.
No imports here: the modules import each other.
"""
