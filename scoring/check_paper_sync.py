#!/usr/bin/env python3
# HolyTrinity Bench — LaTeX/Markdown rendering-sync gate (Python 3, standard library only).
#
#   python3 scoring/check_paper_sync.py
#   python3 scoring/check_paper_sync.py --verbose
#   python3 scoring/check_paper_sync.py papers/some.tex SOME.md    # ad-hoc pair
#
# This repository ships each paper twice: a LaTeX source (the archival/submission form) and
# a Markdown rendering (the form people actually read on GitHub). The two have drifted twice
# in this project's history, and BOTH times the Markdown carried a number the LaTeX had
# already retracted — a `57/73` denominator, and an "observed 47" effect-log claim. Both were
# caught by a human reading carefully. That does not scale, and it did not catch the first
# one. This tool turns that drift into a failing gate.
#
# What it checks, in order of how much it matters:
#
#   1. NUMBERS.  Every numeric claim on both sides — integers, decimals, percentages,
#      interval endpoints, DOIs, dates, ORCIDs, commit digits, section references — is
#      extracted, normalized, and compared as a MULTISET. A number present on one side and
#      not the other is a FAILURE. This is the check that would have caught both drifts.
#
#   2. PROSE.  Both sides are reduced to plain text, split into sentence-level segments, and
#      the segments are diffed. Renderings legitimately differ in ways that carry no meaning,
#      so raw segment divergence does NOT fail on its own: each diverging segment must be
#      explained by one of the named artifact classes in ARTIFACT_CLASSES below. Anything
#      unexplained is a FAILURE.
#
#   3. SIMILARITY.  An 8-gram Jaccard score is printed for every pair, passing or failing, so
#      slow drift is visible as a trend rather than only at the moment it breaks the gate.
#
# Exit status (same convention as ./verify.py):
#
#   0  every pair is in sync
#   1  drift detected — a numeric divergence, or a prose divergence no artifact class explains
#   2  cannot run — a file is missing or unreadable, including a rendering that does not exist
#      yet (reported as SKIPPED, never as a pass). `--allow-skipped` downgrades a SKIPPED pair
#      to advisory so a pair whose rendering is still being written does not block the rest.
#
# Output is deterministic: no timestamps, no absolute paths, no dependence on dict ordering.
# Every path is printed relative to the repository root, and every list is sorted before it
# is printed. Same inputs, same bytes.
#
# No third-party packages: `difflib`, `re`, `collections` and `unicodedata` are standard
# library. Minimum runtime Python 3.6; verified on Python 3.12.3.

import collections
import difflib
import os
import re
import sys
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# The pairs this gate is responsible for. Source of truth first, rendering second.
PAIRS = [
    ("papers/authority-bound-agentic-execution.tex", "PAPER.md"),
    ("papers/the-model-proposes-the-system-authorizes.tex", "PAPER-ARCHITECTURE.md"),
]

# ---------------------------------------------------------------------------
# What this gate forgives, and why
# ---------------------------------------------------------------------------
#
# A rendering is not a copy. pandoc-shaped Markdown and LaTeX express the same sentence with
# different bytes, and a gate that failed on every such difference would be turned off within
# a week — which is the failure mode that lets a real retraction slip through. So a fixed,
# named list of difference classes is forgiven, and NOTHING ELSE IS.
#
# Each entry is (id, layer, what it forgives / why it is safe). `layer` says where the
# forgiveness is applied:
#
#   "markup"  — removed while reducing either side to plain text (STRUCTURAL). These strip
#               notation, never content: a macro name or a table pipe cannot carry a claim.
#   "fold"    — applied ONLY to segments that already diverge, one class at a time, to see
#               which class explains the divergence (see classify_divergence). A segment no
#               fold explains is reported and FAILS.
#
# Adding to this list widens what the gate will not see. Do not add an entry to make a run
# green: if a divergence is not on this list, either it is a real defect in the rendering, or
# the entry you are about to write is a new, genuinely meaning-free rendering difference and
# belongs here with its own explanation.
ARTIFACT_CLASSES = [
    ("reference-numbering", "fold",
     "Reference lists: LaTeX `\\item` inside `enumerate` auto-numbers; the Markdown must "
     "write `1.` … `15.` literally. Same references, same order — the numerals exist only "
     "on one side because the other side generates them at compile time. Bullet markers "
     "(`\\item` vs `- `) are the same case."),

    ("section-numbering", "fold",
     "`\\section{Evaluation}` numbers itself; `## 6. Evaluation` cannot, so the Markdown "
     "carries the numeral in the heading text. Only a numbering prefix at the START of a "
     "heading segment is forgiven — a section number quoted inside a sentence (`see §6.4`) "
     "is ordinary text on both sides and is compared."),

    ("title-byline-abstract", "fold",
     "`\\title`/`\\author`/`\\date`/`\\maketitle` place the title block by macro and "
     "`\\begin{abstract}` labels the abstract implicitly; the Markdown writes a byline line "
     "and an explicit `## Abstract` heading. Placement and the literal word 'Abstract' "
     "differ; the title, author, ORCID and date TEXT is compared like any other content."),

    ("horizontal-rules", "markup",
     "`\\begin{center}\\rule{0.5\\linewidth}{0.5pt}\\end{center}` versus a Markdown `---`. "
     "A separator carries no claim, and its LaTeX form carries dimensions (0.5, 0.5pt) that "
     "would otherwise pollute the numeric multiset with typography."),

    ("hyphenation-hints", "fold",
     "`-\\/-` and `\\-` are LaTeX line-breaking hints inside long identifiers. They render "
     "as nothing and as `--`/`-`. Purely typographic."),

    ("table-scaffolding", "markup",
     "longtable column specs (`\\real{0.1667}`, `\\columnwidth`, `\\tabcolsep`), "
     "`\\toprule`/`\\midrule`/`\\bottomrule`, `\\endhead`, `\\minipage` header wrappers and "
     "row/column separators (`&`, `\\\\`) versus Markdown `|` cells and `|---|` separator "
     "rows. Cell CONTENT is compared in row order; only the grid is dropped. Note that the "
     "column widths are real numbers, so this class is also what keeps table geometry out of "
     "the numeric check."),

    ("code-block-segmentation", "fold",
     "`\\begin{verbatim}` … `\\end{verbatim}` versus ```` ```bash ```` fences. The fence "
     "info string, and the fact that the two forms break the block into segments at "
     "different points, are forgiven; every line of code inside is still compared, including "
     "its numbers."),

    ("symbol-rendering", "fold",
     "The same symbol spelled for two typesetters: `$\\mu$s`/µs, `$\\le$`/≤, `$\\approx$`/≈, "
     "`$\\rightarrow$`/→, `` ``…'' ``/“…”, `--`/–, `\\S`/§, `\\%`/%, `\\_`/_. Rendering of "
     "one character, not a change of claim. Letter case is folded with it: which words a "
     "heading capitalizes is a rendering choice, and no numeric claim depends on case."),

    # --- conditional: only for a source that auto-generates these numbers ----------------
    # The two classes below are enabled ONLY when the LaTeX source actually uses `\ref` /
    # `\cite` / `\bibitem`, i.e. only when LaTeX — not the author — produces the numeral. In
    # a pandoc-shaped source that writes `\S6.4` and `{[}15{]}` literally, both sides carry
    # the author's own numeral, so it is compared strictly and these folds stay OFF. The
    # per-pair report says which folds were enabled and why.
    ("citation-numbering", "fold/conditional",
     "`\\cite{zou2025}` renders as `[31]`: the key is in the source, the numeral is in the "
     "rendering, and neither exists on the other side. The bracketed marker and the "
     "`\\bibitem` key are dropped from both; the reference TEXT (authors, title, venue, "
     "year, DOI, arXiv id) is compared in full, which is where a citation actually drifts. "
     "Footnote markers (`\\footnote{…}` vs `[^1]`) are the same case; the footnote body is "
     "compared as ordinary text."),

    ("cross-reference-resolution", "fold/conditional",
     "`Section~\\ref{sec:gaps}` renders as `Section 13`. The numeral is produced by LaTeX at "
     "compile time and exists only in the rendering, so `Section N`, `Sections N and M`, "
     "`Table N`, `Figure N` and `Appendix N` lose their numeral on both sides. This is the "
     "sharpest thing this gate gives up: a wrong cross-reference number in a rendering is "
     "invisible. It is given up only for sources that use `\\ref`, because for those there "
     "is no number in the source to compare against."),
]

ARTIFACT_IDS = [c[0] for c in ARTIFACT_CLASSES]

# Folds applied only when the LaTeX source auto-generates the numbers in question.
CONDITIONAL_FOLDS = ("citation-numbering", "cross-reference-resolution")
AUTONUMBER_MARKERS = re.compile(r"\\(?:ref|autoref|pageref|eqref|cite[a-zA-Z]*|bibitem)\s*\{")

# ---------------------------------------------------------------------------
# Layer A — reduce each side to plain text (markup only; content is never dropped)
# ---------------------------------------------------------------------------

# Whole LaTeX lines that are table geometry and nothing else — a pandoc longtable column
# spec. Dropping the line is what keeps `\real{0.1667}` and `8\tabcolsep` out of the numeric
# multiset (`table-scaffolding`).
TEX_SCAFFOLD_LINE = re.compile(r"\\real\{|\\columnwidth|\\tabcolsep")

# Environments whose `\begin{env}{...}` mandatory argument is a column spec, not content.
TEX_SPEC_ENVS = ("tabular", "tabular*", "tabularx", "array", "longtable", "minipage",
                 "adjustbox", "supertabular", "thebibliography")

# Environments that wrap part of a line rather than a block. pandoc puts every longtable
# HEADER CELL in its own `minipage`, so breaking a paragraph at them would shred one table
# row into one segment per cell (`table-scaffolding`).
TEX_INLINE_ENVS = ("minipage", "center", "small", "footnotesize", "scriptsize",
                   "flushleft", "flushright", "adjustbox")

# Text-level LaTeX macros whose ARGUMENT is content and whose name is notation.
TEX_UNWRAP = ("textbf", "textit", "texttt", "textsc", "emph", "text", "underline",
              "passthrough", "mbox", "footnotesize", "small", "scriptsize", "caption",
              "textnormal", "uline", "textsuperscript")

# LaTeX escapes and symbol macros -> the character pandoc renders them as. The boundary is
# `(?![a-zA-Z])`, never `\b`: `\textasciitilde19` has no word boundary after the macro name,
# and getting that wrong silently drops the `~` from every "~19 ms" in the paper.
_NB = r"(?![a-zA-Z])"
TEX_LITERALS = [
    (r"\\%", "%"), (r"\\&", "&"), (r"\\_", "_"), (r"\\#", "#"), (r"\\\$", "$"),
    (r"\\\{", "{"), (r"\\\}", "}"),
    (r"\\textbackslash\s*\{\}|\\textbackslash" + _NB, "\\"),
    (r"\\textasciitilde\s*\{\}|\\textasciitilde" + _NB, "~"),
    (r"\\textasciicircum\s*\{\}|\\textasciicircum" + _NB, "^"),
    (r"\\textless\s*\{\}|\\textless" + _NB, "<"),
    (r"\\textgreater\s*\{\}|\\textgreater" + _NB, ">"),
    (r"\\S" + _NB, "\u00a7"),
    (r"\\(?:ldots|dots)" + _NB, "..."),
    (r"\\times" + _NB, "\u00d7"), (r"\\pm" + _NB, "\u00b1"),
    (r"\\(?:leq|le)" + _NB, "\u2264"), (r"\\(?:geq|ge)" + _NB, "\u2265"),
    (r"\\approx" + _NB, "\u2248"), (r"\\sim" + _NB, "~"),
    (r"\\leftrightarrow" + _NB, "\u2194"),
    (r"\\(?:rightarrow|to)" + _NB, "\u2192"), (r"\\leftarrow" + _NB, "\u2190"),
    (r"\\mu" + _NB, "\u00b5"), (r"\\alpha" + _NB, "\u03b1"),
    (r"\\beta" + _NB, "\u03b2"), (r"\\degree" + _NB, "\u00b0"),
]

# Marks a segment that came from the title block, on either side. Stripped before any
# comparison; its only job is to let an unmatched front-matter segment be credited to
# `title-byline-abstract` instead of being reported as drift.
FRONT = "\x02"

# Marks a real paragraph boundary in the LaTeX side while macros are being removed. Removing
# a macro must never CREATE a boundary; see tex_to_text.
PARA = "\x03"


class SourceError(Exception):
    """A file that cannot be read or parsed. Exits 2 (cannot run), never 1 (drift)."""


def strip_tex_comments(text):
    """Drop `%` comments without touching an escaped `\\%`."""
    out = []
    for line in text.split("\n"):
        i, kept = 0, []
        while i < len(line):
            if line[i] == "\\" and i + 1 < len(line):
                kept.append(line[i:i + 2])
                i += 2
                continue
            if line[i] == "%":
                break
            kept.append(line[i])
            i += 1
        out.append("".join(kept))
    return "\n".join(out)


def brace_arg(text, open_idx):
    """text[open_idx] == '{'. Return (body, index_just_after_matching_close)."""
    depth, i = 0, open_idx
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i], i + 1
        i += 1
    raise SourceError("unbalanced braces starting at offset %d" % open_idx)


def unwrap_macros(text, names):
    """`\\textbf{x}` -> `x`, recursively, brace-balanced (regex cannot nest)."""
    pattern = re.compile(r"\\(?:%s)\s*(?=\{)" % "|".join(names))
    while True:
        m = pattern.search(text)
        if not m:
            return text
        body, after = brace_arg(text, m.end())
        # `{\noindent\emph{Author note}}` — splicing the body straight in would produce
        # `\noindentAuthor`, and the next pass, which deletes control words, would delete the
        # word "Author" with it. A control word ends at the first non-letter, so put one back.
        head = text[:m.start()]
        k = len(head)
        while k > 0 and head[k - 1].isalpha():
            k -= 1
        if k > 0 and k < len(head) and head[k - 1] == "\\":
            head += " "
        text = head + body + text[after:]


def expand_newcommands(preamble, body):
    """Expand the paper's own `\\newcommand`s, because a macro's expansion is CONTENT.

    `\\newcommand{\\mech}[2]{\\subsection{Mechanism #1: #2}}` means the word "Mechanism" is
    written once in the source and nine times in the rendering. Without expansion every one
    of those headings would look like drift. Only simple, non-recursive definitions with
    brace-group arguments are expanded; anything else is left alone and, if it matters, will
    surface as an unclassified divergence rather than being silently forgiven.
    """
    defs = {}
    for m in re.finditer(r"\\(?:new|renew|provide)command\*?\s*\{\\([a-zA-Z]+)\}\s*"
                         r"(?:\[(\d)\])?\s*(?=\{)", preamble):
        try:
            template = brace_arg(preamble, m.end())[0]
        except SourceError:
            continue
        defs[m.group(1)] = (int(m.group(2) or 0), template)

    for name, (argc, template) in sorted(defs.items()):
        if argc == 0:
            body = re.sub(r"\\" + name + r"(?![a-zA-Z])(\{\})?",
                          lambda _m, t=template: t, body)
            continue
        pattern = re.compile(r"\\" + name + r"(?![a-zA-Z])\s*(?=\{)")
        guard = 0
        while guard < 500:
            m = pattern.search(body)
            if not m:
                break
            args, pos = [], m.end()
            try:
                for _ in range(argc):
                    arg, pos = brace_arg(body, pos)
                    args.append(arg)
            except SourceError:
                break
            out = template
            for i, arg in enumerate(args, 1):
                out = out.replace("#%d" % i, arg)
            body = body[:m.start()] + out + body[pos:]
            guard += 1
    return body


# LaTeX accent macros -> the combining mark pandoc renders them as. `Balunovi\'{c}` and
# `Balunović` are the same author, and a citation is exactly where that matters.
ACCENTS = {"'": "\u0301", "`": "\u0300", '"': "\u0308", "^": "\u0302", "~": "\u0303",
           "=": "\u0304", ".": "\u0307", "u": "\u0306", "v": "\u030c", "c": "\u0327",
           "H": "\u030b", "r": "\u030a", "k": "\u0328", "d": "\u0323", "b": "\u0331"}
ACCENT_RE = re.compile(r"\\([`'\"^~=.]|[uvcHrkdb](?=\{))\s*(?:\{([a-zA-Z])\}|([a-zA-Z]))")


def apply_accents(text):
    def rep(m):
        letter = m.group(2) or m.group(3)
        return unicodedata.normalize("NFC", letter + ACCENTS[m.group(1)])
    return ACCENT_RE.sub(rep, text)


def strip_definitions(text):
    """Remove `\\def\\x{…}` / `\\newcommand{\\x}[n]{…}` bodies (brace-balanced)."""
    pattern = re.compile(r"\\(?:def\s*\\[a-zA-Z]+|(?:new|renew|provide)command\*?\s*"
                         r"\{\\[a-zA-Z]+\}(?:\[\d\])?(?:\[[^\]]*\])?)\s*(?=\{)")
    guard = 0
    while guard < 500:
        m = pattern.search(text)
        if not m:
            return text
        try:
            after = brace_arg(text, m.end())[1]
        except SourceError:
            return text
        text = text[:m.start()] + " " + text[after:]
        guard += 1
    return text


def tex_to_text(raw):
    """LaTeX -> plain text. Removes notation; never removes a word or a number."""
    text = strip_tex_comments(raw)

    m = re.search(r"\\begin\{document\}", text)
    preamble = text[:m.start()] if m else ""
    body = text[m.end():] if m else text
    end = re.search(r"\\end\{document\}", body)
    if end:
        body = body[:end.start()]

    # \title / \author / \date live in the preamble but ARE content: the byline carries the
    # ORCID and the date, both of which the Markdown prints. Everything else in the preamble
    # is typesetting (font sizes, lengths, package options) and is dropped with it.
    front = []
    for cmd in ("title", "author", "date"):
        mm = re.search(r"\\" + cmd + r"\s*(?=\{)", preamble)
        if mm:
            arg = re.sub(r"\\\\(\[[^\]]*\])?", " ", brace_arg(preamble, mm.end())[0])
            front.append(FRONT + arg)
    text = "\n\n".join(front) + "\n\n" + body

    # Definitions may sit in the preamble or in the body (pandoc emits `\def\labelenumi{…}`
    # right before a list). Expand from both, then delete the definitions themselves: a
    # definition is instructions to the typesetter, not text.
    text = expand_newcommands(preamble + "\n" + body, text)
    text = strip_definitions(text)

    # Protect verbatim blocks: their content is code, and backslashes in it are data.
    verbatims = []

    def _stash(m):
        verbatims.append(m.group(1))
        return PARA + "\x00VERB%d\x00" % (len(verbatims) - 1) + PARA

    text = re.sub(r"\\begin\{(?:verbatim|lstlisting)\}\n?(.*?)\\end\{(?:verbatim|lstlisting)\}",
                  _stash, text, flags=re.S)

    text = "\n".join(l for l in text.split("\n") if not TEX_SCAFFOLD_LINE.search(l))

    # A footnote is content, but the rendering moves it out of the sentence. Segments are
    # compared as a multiset, so lifting the body to its own paragraph keeps BOTH the
    # sentence and the footnote comparable (`citation-numbering`).
    footnotes = []
    while True:
        m = re.search(r"\\footnote(?:mark|text)?\s*(?=\{)", text)
        if not m:
            break
        body_fn, after = brace_arg(text, m.end())
        footnotes.append(body_fn)
        text = text[:m.start()] + " " + text[after:]
    if footnotes:
        # Re-attached HERE, not after normalization: a footnote body is LaTeX like any other
        # and has to go through the same macro removal, or its `\cite{zou2025}` key survives
        # into the numeric multiset as a phantom "2025".
        text = text + "\n\n" + "\n\n".join(footnotes)

    # Fix the paragraph boundaries NOW, before any macro is removed. Deleting `\midrule` or
    # `\end{minipage}` leaves a whitespace-only line behind, and a whitespace-only line looks
    # exactly like a paragraph break — which is how a five-column table header ends up as
    # five separate "paragraphs" on one side and one row on the other. From here on, only an
    # explicit PARA is a boundary; every other newline is line-wrapping and collapses.
    text = re.sub(r"\n[ \t]*\n\s*", PARA, text)

    # Accents first: `\~{n}` must be spent before `~` is treated as a tie.
    text = apply_accents(text)
    text = re.sub(r"\\char`\\?(.)", r"\1", text)   # `\char`_` -> `_`
    text = text.replace("~", " ")   # a LaTeX tie, before \textasciitilde mints a real one
    # The column separator, spent BEFORE `\&` becomes a literal `&` — otherwise the cleanup
    # eats the ampersand out of "Posture \& freeze".
    text = re.sub(r"(?<!\\)&", " ", text)
    text = re.sub(r"\\label\s*\{[^}]*\}", " ", text)
    text = re.sub(r"\\hypertarget\s*\{[^}]*\}", " ", text)
    text = re.sub(r"\\(?:hspace|vspace|setlength|setlist|rule|arraystretch)\*?\s*"
                  r"(\{[^{}]*\}){1,2}", " ", text)
    text = re.sub(r"\\href\s*\{([^}]*)\}\s*(?=\{)", r" \1 ", text)
    text = re.sub(r"\\url\s*\{([^}]*)\}", r" \1 ", text)
    # `\cite{key}` / `\bibitem{key}`: the key is notation, the numeral it renders as lives
    # only on the Markdown side (`citation-numbering`). `\ref{}` likewise.
    text = re.sub(r"\\(?:cite[a-zA-Z]*|bibitem)\s*(\[[^\]]*\])?\s*\{[^}]*\}", " ", text)
    # A CHAIN of cross-references (`Sections~\ref{a},~\ref{b}, and~\ref{c}`) goes together
    # with the punctuation that joins it: leaving `Sections,, and` behind would look like
    # drift against the rendering's `Sections 5, 8, and 9`.
    _ref = r"\\(?:ref|autoref|pageref|eqref|nameref)\s*\{[^}]*\}"
    text = re.sub(r"%s(?:\s*(?:,\s*)?(?:and\s+|to\s+|through\s+)?%s)*" % (_ref, _ref),
                  " ", text)

    for pat, rep in TEX_LITERALS:
        text = re.sub(pat, rep.replace("\\", "\\\\"), text)

    text = text.replace("{[}", "[").replace("{]}", "]")
    text = unwrap_macros(text, TEX_UNWRAP)
    # A heading is its own segment, opened AND closed: `\mech{M1}{…}` expands to a
    # `\subsection` that is not followed by a blank line, and without the closing break the
    # heading would be glued to the paragraph under it.
    heading = re.compile(r"\\(?:section|subsection|subsubsection|paragraph)\*?\s*(?=\{)")
    guard = 0
    while guard < 500:
        m = heading.search(text)
        if not m:
            break
        try:
            title, after = brace_arg(text, m.end())
        except SourceError:
            break
        text = text[:m.start()] + PARA + title + PARA + text[after:]
        guard += 1

    # Row and cell separators: `table-scaffolding`. One table row becomes one segment on both
    # sides, so a disagreement names the row it is in.
    text = re.sub(r"\\tabularnewline|\\\\(\[[^\]]*\])?[ \t]*\n?", PARA, text)
    text = re.sub(r"\\[ ,;:!]", " ", text)   # \, \; \: and the escaped space `\ `
    # A list item becomes its own segment on both sides (`reference-numbering`). A
    # description-list item carries its TERM in the optional argument (`\item[Authority]`),
    # which is content and is kept.
    text = re.sub(r"\\item\b\s*\[([^\]]*)\]", lambda m: PARA + m.group(1) + ": ", text)
    text = re.sub(r"\\item\b", PARA, text)
    text = drop_environments(text)
    text = re.sub(r"\\[a-zA-Z@]+\*?", " ", text)   # any macro name left is notation
    text = text.replace("``", '"').replace("''", '"')
    # `$` is a delimiter, not a character: dropping it (rather than replacing it with a
    # space) is what keeps `0$\rightarrow$10` identical to the rendered `0→10`.
    text = text.replace("{", " ").replace("}", " ").replace("$", "")

    text = text.replace("\n", " ").replace(PARA, "\n\n")
    for i, v in enumerate(verbatims):
        text = text.replace("\x00VERB%d\x00" % i, v)
    return text


def drop_environments(text):
    """`\\begin{env}[opt]{spec}` / `\\end{env}` -> a paragraph break.

    The mandatory `{...}` is dropped only for environments where it is a column spec
    (`p{0.7cm}p{4.7cm}` is geometry, not content) — brace-balanced, because a column spec
    nests braces and a regex cannot.
    """
    out, i = [], 0
    pattern = re.compile(r"\\(begin|end)\s*\{([a-zA-Z*]+)\}")
    while True:
        m = pattern.search(text, i)
        if not m:
            out.append(text[i:])
            return "".join(out)
        out.append(text[i:m.start()])
        out.append(" " if m.group(2) in TEX_INLINE_ENVS else PARA)
        j = m.end()
        opt = re.match(r"\s*\[[^\]]*\]", text[j:])
        if opt:
            j += opt.end()
        if m.group(1) == "begin" and m.group(2) in TEX_SPEC_ENVS:
            k = re.match(r"\s*(?=\{)", text[j:])
            if k:
                try:
                    j = brace_arg(text, j + k.end())[1]
                except SourceError:
                    # A multi-line pandoc column spec whose `\real{…}` lines were already
                    # dropped as scaffolding leaves an unclosed `{@{}`. Nothing numeric is
                    # left in it; skip to the end of the line and let the generic cleanup
                    # take the residue.
                    nl = text.find("\n", j)
                    j = len(text) if nl < 0 else nl
        i = j


MD_TABLE_SEPARATOR = re.compile(r"^\s*\|[\s:|+-]*\|\s*$")


def md_to_text(raw):
    """Markdown -> plain text. Same contract as tex_to_text."""
    lines, out, in_fence = raw.split("\n"), [], False
    # The title block: the leading H1 and the byline paragraph under it. Marked, not dropped
    # — its numbers (ORCID, date) are still compared; only its SHAPE is forgiven, because
    # LaTeX builds it from \title/\author/\date and Markdown writes one line by hand.
    seen_h1, front_done = False, False
    for i, line in enumerate(lines):
        if front_done:
            break
        if not line.strip():
            continue
        if not seen_h1 and re.match(r"^#\s+\S", line):
            lines[i] = FRONT + line
            seen_h1 = True
            continue
        if seen_h1:
            if re.match(r"^#{1,6}\s", line) or re.match(r"^\s*(?:-{3,}|\*{3,})\s*$", line):
                front_done = True
                continue
            lines[i] = FRONT + line
            front_done = True

    for line in lines:
        if re.match(r"^\s*```", line):
            # `code-block-segmentation`: the fence and its info string are notation.
            in_fence = not in_fence
            out.append("")
            continue
        if in_fence:
            out.append(line)
            continue
        if MD_TABLE_SEPARATOR.match(line):        # `table-scaffolding`
            out.append("")
            continue
        if re.match(r"^\s*(?:-{3,}|\*{3,}|_{3,})\s*$", line):   # `horizontal-rules`
            out.append("")
            continue
        if "|" in line and line.strip().startswith("|"):
            # One table row = one segment, matching the LaTeX `\\` row break. Done HERE, in
            # the same pass as the heading test, because a header row's first cell is often
            # literally `#` — and a `#` at the start of a line, tested later, looks exactly
            # like an H1 marker.
            line = "\n" + line.strip().strip("|").replace("|", " ") + "\n"
        elif re.match(r"^(\x02?)\s{0,3}#{1,6}\s+\S", line):        # heading markers
            line = re.sub(r"^(\x02?)\s{0,3}#{1,6}\s*", r"\n\n\1", line) + "\n"
        # A list item becomes its own segment, matching `\item` on the LaTeX side. The
        # marker itself is left in place for the folds to strip and credit.
        elif re.match(r"^\s*(?:[-*+]|\d{1,3}[.)])\s+\S", line):
            line = "\n" + re.sub(r"^\s*[-*+]\s+", "", line.strip())
        out.append(line)
    text = "\n".join(out)
    # Footnote definitions and markers (`citation-numbering`): the body is kept and compared
    # as an ordinary paragraph, exactly as `\footnote{…}` is on the LaTeX side.
    text = re.sub(r"^\s*\[\^[^\]]+\]:\s*", "\n\n", text, flags=re.M)
    text = re.sub(r"\[\^[^\]]+\]", " ", text)
    text = re.sub(r"!\[([^\]]*)\]\(([^)]*)\)", r" \1 \2 ", text)
    text = re.sub(r"\[([^\]]*)\]\(([^)]*)\)", r" \1 \2 ", text)
    text = text.replace("`", "")
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text, flags=re.S)
    text = re.sub(r"(?<!\w)\*(?!\s)(.+?)(?<!\s)\*(?!\w)", r"\1", text, flags=re.S)
    text = re.sub(r"^\s*>\s?", "", text, flags=re.M)                # block quotes
    return text


# ---------------------------------------------------------------------------
# Layer B — the folds, one per artifact class (applied only to diverging segments)
# ---------------------------------------------------------------------------

SYMBOL_MAP = [
    ("\u2018", "'"), ("\u2019", "'"), ("\u201c", '"'), ("\u201d", '"'),
    ("\u2013", "-"), ("\u2014", "-"), ("\u2212", "-"), ("\u2010", "-"),
    ("\u00a0", " "), ("\u2009", " "), ("\u202f", " "), ("\u200b", ""),
    ("\u2026", "..."), ("\u2192", "->"), ("\u2190", "<-"),
    ("\u2194", "<->"), ("\u2264", "<="), ("\u2265", ">="), ("\u2248", "~"), ("\u00b7", " "),
    ("\u00d7", "x"), ("\u00b5", "u"), ("\u03bc", "u"), ("\u00a7", "S"),
]


def fold_symbol_rendering(s):
    s = unicodedata.normalize("NFKC", s)
    # `Sec. 9.1` and `§9.1` are the same reference, differently spelled: LaTeX `verbatim`
    # cannot carry a `§` portably, so a comment inside a code block spells it out. Narrow on
    # purpose — only when a digit follows, so "3 sec." (a duration) is untouched.
    s = re.sub(r"\b[Ss]ec\.\s*(?=\d)", "§", s)
    for a, b in SYMBOL_MAP:
        s = s.replace(a, b)
    s = re.sub(r"-{2,}", "-", s)
    s = re.sub(r"\s+", " ", s)
    s = re.sub(r"\s+([,.;:!?)\]])", r"\1", s)   # `\url{…} .` -> `… .` -> `….`
    s = re.sub(r"([(\[])\s+", r"\1", s)
    return s.strip().lower()


def fold_hyphenation_hints(s):
    return s.replace("-\\/-", "--").replace("\\/", "").replace("\\-", "")


def fold_section_numbering(s):
    # A numbering prefix, and only at the start of a segment: `6.4 Statistical power`.
    s = re.sub(r"^\d+(?:\.\d+)*\.?\s+(?=[A-Za-z\"'(])", "", s)
    # `\appendix` letters the appendices; the Markdown heading writes `Appendix A:` out.
    return re.sub(r"^appendix\s+[A-Z]\s*[:.]\s*", "", s, flags=re.I)


def fold_reference_numbering(s):
    # An ordered-list marker at the start of a segment: `12. K. Greshake et al. …`.
    s = re.sub(r"^\d{1,3}[.)]\s+", "", s)
    # `\begin{thebibliography}` prints its own "References" heading; the Markdown writes one.
    return re.sub(r"^(?:references|bibliography|works cited)\s*$", "", s, flags=re.I)


def fold_title_byline_abstract(s):
    s = s.replace(FRONT, "")
    s = re.sub(r"^(?:abstract|keywords|index terms)\s*[:.]?\s*", "", s, flags=re.I)
    return re.sub(r"^\s*[:.]\s*", "", s)   # the colon left behind by a bolded `Keywords:`


def fold_code_block_segmentation(s):
    # Fence info strings (```bash) and the `#` comment column of a shell line.
    return re.sub(r"^(?:bash|sh|text|console|elixir|json|python)\b\s*", "", s)


def fold_horizontal_rules(s):
    return re.sub(r"^[-*_\u2014\u2013\s]+$", "", s)


def fold_table_scaffolding(s):
    s = re.sub(r"\s*\|\s*", " ", s).strip()
    # A caption LABEL: `\caption{…}` auto-numbers, so the Markdown writes `Table 2:` by hand.
    # The caption text itself is untouched and compared.
    return re.sub(r"^(?:table|figure|fig\.|listing|algorithm)\s*\d*\s*[:.]\s*", "", s,
                  flags=re.I)


def fold_citation_numbering(s):
    # `[31]`, `[23, 24]`, `[15, ref. 11]` — a bracketed citation marker, and the footnote
    # markers that render the same way. Enabled only for a `\cite`-using source.
    s = re.sub(r"\[\s*\d{1,3}(?:\s*[,;-]\s*\d{1,3})*\s*\]", " ", s)
    return re.sub(r"\[\^[^\]]*\]", " ", s)


CROSSREF = re.compile(
    r"\b(sections?|tables?|figures?|appendix|appendices|equations?|listings?|algorithms?)"
    r"(\s+\d+(?:\.\d+)*"
    r"(?:(?:\s*,\s*|\s+)(?:and\s+|to\s+|through\s+)?\d+(?:\.\d+)*)*)",
    re.I)


def fold_cross_reference_resolution(s):
    # `Section 13` / `Sections 4 and 5` -> the word alone. Enabled only for a `\ref`-using
    # source, where the numeral exists on one side only.
    return CROSSREF.sub(lambda m: m.group(1), s)


# Order matters twice over: `fold_all` applies these in sequence, and `classify_divergence`
# credits the FIRST one that changes a diverging segment — so the specific classes come
# first and the catch-all symbol/whitespace/case fold comes last.
FOLDS = collections.OrderedDict([
    ("hyphenation-hints", fold_hyphenation_hints),
    ("section-numbering", fold_section_numbering),
    ("reference-numbering", fold_reference_numbering),
    ("title-byline-abstract", fold_title_byline_abstract),
    ("code-block-segmentation", fold_code_block_segmentation),
    ("horizontal-rules", fold_horizontal_rules),
    ("table-scaffolding", fold_table_scaffolding),
    ("citation-numbering", fold_citation_numbering),
    ("cross-reference-resolution", fold_cross_reference_resolution),
    ("symbol-rendering", fold_symbol_rendering),
])

ALWAYS_ON = frozenset(n for n in FOLDS if n not in CONDITIONAL_FOLDS)


def fold_all(s, enabled=ALWAYS_ON):
    for name, fn in FOLDS.items():
        if name in enabled:
            s = fn(s)
    return s


# ---------------------------------------------------------------------------
# Segmentation and the two comparisons
# ---------------------------------------------------------------------------

SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[\"'(\[]?[A-Z0-9\u00a7])")

# Abbreviations whose period does not end a sentence. Without these, `(Sec. 9.1)` becomes two
# segments on the side that spells it that way and one on the side that writes `(\u00a79.1)`.
ABBREVIATION_END = re.compile(
    r"(?:^|[\s(\[])(?:sec|fig|no|vs|al|eq|ref|cf|ch|pp|vol|approx|ca|est|dr|mr|mrs|prof|"
    r"inc|ltd|etc|e\.g|i\.e|resp|cap|art|para|tbl|tab|app)\.$", re.I)


def segments(text):
    """Plain text -> comparable sentence-level segments, in document order."""
    out = []
    for block in re.split(r"\n\s*\n", text):
        block = re.sub(r"\s+", " ", block).strip()
        if not block:
            continue
        sents = [s.strip() for s in SENTENCE_SPLIT.split(block) if s.strip()]
        # `1. J. P. Anderson.` splits after the list marker, which would leave `1.` as a
        # segment of its own and hide the reference behind it. Re-attach it, so the marker
        # stays visible to the `reference-numbering` fold instead of being pre-stripped.
        merged = []
        for sent in sents:
            if merged and (re.match(r"^\d{1,3}[.)]$", merged[-1])
                           or ABBREVIATION_END.search(merged[-1])):
                merged[-1] = merged[-1] + " " + sent
            else:
                merged.append(sent)
        out.extend(merged)
    return out


# A numeric claim: an optionally-signed number, thousands separators tolerated, optional
# decimal part, optional trailing %. Digit runs inside identifiers (F10, nist-p25, an ORCID,
# a commit sha) are captured too — they are claims as much as any other number, and if one
# side renames F10 the multiset says so.
NUMBER = re.compile(r"\d+(?:,\d{3})+(?:\.\d+)?%?|\d+(?:\.\d+)?%?")


def normalize_number(tok):
    """`16,882` -> `16882`; `4.90%` -> `4.9%`; `0.50` -> `0.5`. Value, not spelling."""
    pct = tok.endswith("%")
    body = tok[:-1] if pct else tok
    body = body.replace(",", "")
    if "." in body:
        body = body.rstrip("0").rstrip(".")
        if body == "" or body == "-":
            body = "0"
    else:
        # Preserve leading zeros: `0009-0008-…` (ORCID) and `01` in a filename are labels.
        pass
    return body + ("%" if pct else "")


def numbers_of(text):
    return collections.Counter(normalize_number(t) for t in NUMBER.findall(text))


def shingles(segs, enabled, n=8):
    toks = []
    for seg in segs:
        toks.extend(re.findall(r"[a-z0-9%<>=/.\u00a7-]+", fold_all(seg, enabled)))
    if len(toks) < n:
        return set()
    return set(tuple(toks[i:i + n]) for i in range(len(toks) - n + 1))


def jaccard(a, b):
    if not a and not b:
        return 1.0
    return len(a & b) / float(len(a | b))


def classify_divergence(only_tex, only_md, enabled):
    """Explain each diverging segment with exactly one artifact class, or fail it.

    Strategy: fully fold both sides and re-match. A segment that finds a counterpart only
    after folding is explained; the class credited is the first fold that, applied alone,
    changes that segment (or its counterpart) — that is what the maintainer needs to see.
    A segment with no folded counterpart at all is UNCLASSIFIED and fails.
    """
    folded_md = collections.Counter(fold_all(s, enabled) for s in only_md)
    folded_tex = collections.Counter(fold_all(s, enabled) for s in only_tex)

    explained = collections.Counter()
    unexplained = []

    def credit(seg):
        for name, fn in FOLDS.items():
            if name in enabled and fn(seg) != seg:
                return name
        return "symbol-rendering"   # whitespace/quote/case canonicalization only

    for side, mine, theirs in (("tex", only_tex, folded_md), ("md", only_md, folded_tex)):
        for seg in mine:
            f = fold_all(seg, enabled)
            if theirs.get(f, 0) > 0:
                theirs[f] -= 1
                explained[credit(seg)] += 1
            elif not f:
                # Folded away to nothing: a bare `Abstract` heading, a `---` rule, a stray
                # list marker. There is nothing left to disagree about.
                explained[credit(seg)] += 1
            elif FRONT in seg:
                # Title block. LaTeX splits it into title / author / affiliation / e-mail /
                # ORCID / date; the Markdown writes one byline. Shape only — every number in
                # it is still in the numeric multiset and still compared.
                explained["title-byline-abstract"] += 1
            else:
                unexplained.append((side, seg))
    return explained, unexplained


# ---------------------------------------------------------------------------
# Reporting — mirrors ./verify.py: an `ok`/`FAIL` check block and a `RESULT:` line
# ---------------------------------------------------------------------------


def pad_t(s, n):
    return s + " " * max(0, n - len(s))


class Checker(object):
    def __init__(self):
        self.rows = []

    def check(self, label, actual, expected):
        self.rows.append((label, str(actual), str(expected), str(actual) == str(expected)))

    @property
    def failures(self):
        return [r for r in self.rows if not r[3]]


def read(path):
    try:
        with open(path, "rb") as fh:
            return fh.read().decode("utf-8")
    except IOError as exc:
        raise SourceError("cannot read %s: %s" % (rel(path), exc.strerror or exc))
    except UnicodeDecodeError as exc:
        raise SourceError("%s is not valid UTF-8: %s" % (rel(path), exc))


def rel(path):
    """Repo-relative, so output does not depend on where the tree is checked out.

    A path OUTSIDE the repository (an ad-hoc pair, a self-test probe in a temp directory) is
    reduced to its basename: printing `../../../tmp/…` would leak the checkout location into
    the output and break byte-for-byte reproducibility on another machine.
    """
    try:
        out = os.path.relpath(os.path.abspath(path), ROOT)
    except ValueError:
        return os.path.basename(path)
    return os.path.basename(path) if out.startswith(os.pardir) else out


MAX_SHOWN = 12   # per side, per pair — deterministic truncation, count always reported


def check_pair(out, ck, tex_path, md_path, verbose):
    """Score one pair. Returns 'ok' | 'drift' | 'skipped'."""
    label = "%s -> %s" % (rel(tex_path), rel(md_path))
    out.append("\u2500\u2500 PAIR: " + label + " \u2500\u2500")

    if not os.path.exists(tex_path):
        out.append("  SKIPPED — LaTeX source does not exist: " + rel(tex_path))
        out.append("")
        return "skipped"
    if not os.path.exists(md_path):
        out.append("  SKIPPED — Markdown rendering does not exist yet: " + rel(md_path))
        out.append("            Nothing was checked for this pair. This is NOT a pass:")
        out.append("            the gate exits 2 (cannot run) unless --allow-skipped is given.")
        out.append("")
        return "skipped"

    tex_raw = read(tex_path)
    tex_text = tex_to_text(tex_raw)
    md_text = md_to_text(read(md_path))

    # Which artifact classes apply to THIS pair. The conditional ones are enabled only for a
    # source that auto-generates the numbers they forgive; see ARTIFACT_CLASSES.
    enabled = set(ALWAYS_ON)
    autonumbered = bool(AUTONUMBER_MARKERS.search(tex_raw))
    if autonumbered:
        enabled.update(CONDITIONAL_FOLDS)
    enabled = frozenset(enabled)
    out.append("  conditional classes     %s"
               % ("citation-numbering + cross-reference-resolution ENABLED "
                  "(source uses \\ref/\\cite)" if autonumbered else
                  "none (source writes its own § and [n] numerals — they are compared)"))

    tex_segs, md_segs = segments(tex_text), segments(md_text)

    # --- 1. numbers ---------------------------------------------------------
    # Extracted from the FOLDED SEGMENTS, never from raw lines: the two files wrap at
    # different columns, and a start-anchored fold applied to a wrapped line would eat a
    # number that merely happened to start a line.
    tex_nums = numbers_of("\n".join(fold_all(s, enabled) for s in tex_segs))
    md_nums = numbers_of("\n".join(fold_all(s, enabled) for s in md_segs))
    tex_only_n = tex_nums - md_nums
    md_only_n = md_nums - tex_nums

    out.append("  numeric claims          tex %d (%d distinct)   md %d (%d distinct)"
               % (sum(tex_nums.values()), len(tex_nums),
                  sum(md_nums.values()), len(md_nums)))

    # --- 3. similarity ------------------------------------------------------
    sim = jaccard(shingles(tex_segs, enabled), shingles(md_segs, enabled))
    out.append("  8-gram Jaccard          %.4f" % sim)

    # --- 2. prose -----------------------------------------------------------
    a, b = collections.Counter(tex_segs), collections.Counter(md_segs)
    only_tex, only_md = list((a - b).elements()), list((b - a).elements())
    explained, unexplained = classify_divergence(only_tex, only_md, enabled)

    out.append("  segments                tex %d   md %d   diverging %d"
               % (len(tex_segs), len(md_segs), len(only_tex) + len(only_md)))
    if explained:
        for name in sorted(explained):
            out.append("    forgiven  %s %d" % (pad_t(name, 26), explained[name]))
    if unexplained:
        out.append("    UNCLASSIFIED %d — no artifact class explains these:" % len(unexplained))
        for side, seg in sorted(unexplained)[:MAX_SHOWN]:
            out.append("      %s-only: %s" % (side, clip(seg)))
        if len(unexplained) > MAX_SHOWN:
            out.append("      … %d more (run with --verbose)"
                       % (len(unexplained) - MAX_SHOWN))

    if tex_only_n or md_only_n:
        out.append("    NUMERIC DIVERGENCE — a number on one side is missing from the other:")
        for tok, cnt in sorted(tex_only_n.items()):
            out.append("      in .tex, not in .md:  %-14s x%d" % (tok, cnt))
            for line in sorted(context_lines(tex_text, tok))[:2]:
                out.append("        tex: " + clip(line))
        for tok, cnt in sorted(md_only_n.items()):
            out.append("      in .md, not in .tex:  %-14s x%d" % (tok, cnt))
            for line in sorted(context_lines(md_text, tok))[:2]:
                out.append("        md:  " + clip(line))

    if verbose and (unexplained or tex_only_n or md_only_n):
        out.append("    --- verbose: every diverging segment ---")
        for side, seg in sorted(unexplained):
            out.append("      %s-only: %s" % (side, seg))

    ck.check("numbers agree: " + label,
             "%d tex-only, %d md-only" % (sum(tex_only_n.values()), sum(md_only_n.values())),
             "0 tex-only, 0 md-only")
    ck.check("prose divergence classified: " + label,
             "%d unclassified" % len(unexplained), "0 unclassified")
    out.append("")
    return "ok" if not (tex_only_n or md_only_n or unexplained) else "drift"


def clip(s, width=110):
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= width else s[:width - 1] + "\u2026"


def context_lines(text, token):
    """Every line carrying that number, for the failure message. Sorted by the caller."""
    hits = set()
    for line in text.split("\n"):
        for tok in NUMBER.findall(line):
            if normalize_number(tok) == token:
                hits.add(clip(line))
                break
    return hits


# ---------------------------------------------------------------------------
# Self-test — the gate has to be able to FAIL
# ---------------------------------------------------------------------------
#
# `scoring/test_denominator.py` exists because a check nobody has ever seen fail is not
# evidence that the thing it checks is true. The same applies here, and more sharply: this
# gate's whole job is to fail on a class of change that a human already failed to catch
# twice. So it injects that exact change into a COPY of a rendering, in a temp directory,
# and asserts the gate reports it — and then asserts the untouched pair still passes.
#
#   python3 scoring/check_paper_sync.py --self-test
#
# The injections are deterministic functions of the file's own content: the FIRST multi-digit
# number in the rendering is incremented (the `57/73` shape), and one fabricated sentence is
# appended (a claim the LaTeX never made). Nothing is written inside the repository.


def inject_number(text):
    """Bump the first free-standing multi-digit number: the shape of the `57/73` drift.

    `[\\w.-]` on both sides keeps the probe off ORCIDs, DOIs, CVE ids and version strings —
    the mutation should look like a RESULT that moved, because that is the drift that
    happened twice.
    """
    m = re.search(r"(?<![\w.-])\d{2,4}(?![\w.-])", text)
    if not m:
        return None, None
    old = m.group(0)
    new = str(int(old) + 1)
    return text[:m.start()] + new + text[m.end():], "%s -> %s" % (old, new)


FABRICATED = ("The membrane was disabled for every trial in this campaign and no reviewer "
              "objected.")


def inject_sentence(text):
    """Append a claim the LaTeX never made: the shape of the 'observed 47' drift."""
    return text.rstrip("\n") + "\n\n" + FABRICATED + "\n", FABRICATED


def self_test(argv_verbose):
    import tempfile   # stdlib, and only needed on this path

    out, failures = [], []
    out.append("── SELF-TEST: can this gate fail? ──")

    pair = None
    for tex, md in PAIRS:
        t, m = os.path.join(ROOT, tex), os.path.join(ROOT, md)
        if os.path.exists(t) and os.path.exists(m):
            pair = (t, m)
            break
    if pair is None:
        sys.stdout.write("\n".join(out + ["  cannot self-test: no complete pair on disk", "",
                                          "RESULT: CANNOT RUN — self-test needs one "
                                          "complete pair."]) + "\n")
        return 2

    tex_path, md_path = pair
    original = read(md_path)
    tmpdir = tempfile.mkdtemp(prefix="paper-sync-selftest-")
    try:
        cases = []
        mutated, what = inject_number(original)
        if mutated is not None:
            cases.append(("numeric divergence (%s)" % what, mutated, "drift",
                          what.split(" -> ")[1]))
        mutated, sentence = inject_sentence(original)
        cases.append(("fabricated sentence", mutated, "drift", sentence[:40]))
        cases.append(("untouched rendering", original, "ok", None))

        for label, content, want, evidence in cases:
            probe = os.path.join(tmpdir, "probe.md")
            with open(probe, "wb") as fh:
                fh.write(content.encode("utf-8"))
            buf, ck = [], Checker()
            got = check_pair(buf, ck, tex_path, probe, False)
            # Reacting is not enough: the report has to NAME what changed, or the next
            # maintainer gets a red gate and no idea which number moved.
            named = evidence is None or any(evidence in line for line in buf)
            ok = (got == want) and named
            out.append("  %-4s %-34s expected %-8s got %-8s %s"
                       % ("ok" if ok else "FAIL", label, want, got,
                          "" if evidence is None else
                          ("names %r" % evidence[:40] if named else "DOES NOT NAME IT")))
            if not ok:
                failures.append(label)
            if argv_verbose:
                out.extend("      " + l for l in buf)

        # The missing-rendering path must be SKIPPED, never a silent pass.
        buf, ck = [], Checker()
        got = check_pair(buf, ck, tex_path, os.path.join(tmpdir, "does-not-exist.md"), False)
        ok = (got == "skipped")
        out.append("  %-4s %-34s expected %-8s got %s"
                   % ("ok" if ok else "FAIL", "missing rendering", "skipped", got))
        if not ok:
            failures.append("missing rendering")
    finally:
        for name in sorted(os.listdir(tmpdir)):
            os.remove(os.path.join(tmpdir, name))
        os.rmdir(tmpdir)

    out.append("")
    if failures:
        out.append("RESULT: FAIL — the gate did not react to %d injected change(s): %s"
                   % (len(failures), ", ".join(sorted(failures))))
    else:
        out.append("RESULT: PASS — the gate fails on injected drift and passes on the "
                   "real pair.")
    sys.stdout.write("\n".join(out) + "\n")
    return 1 if failures else 0


USAGE = """usage: python3 scoring/check_paper_sync.py [--verbose] [--allow-skipped]
       python3 scoring/check_paper_sync.py [--verbose] <paper.tex> <paper.md>
       python3 scoring/check_paper_sync.py --self-test [--verbose]

Checks that every Markdown rendering still says what its LaTeX source says.
Exit 0 = in sync, 1 = drift, 2 = cannot run (a file is missing or unreadable).
"""


def main(argv):
    verbose = "--verbose" in argv
    allow_skipped = "--allow-skipped" in argv
    rest = [a for a in argv[1:] if not a.startswith("--")]
    bad = [a for a in argv[1:] if a.startswith("--")
           and a not in ("--verbose", "--allow-skipped", "--self-test")]
    if bad or len(rest) not in (0, 2):
        sys.stderr.write(USAGE)
        return 2
    if "--self-test" in argv:
        return self_test(verbose)

    pairs = [(rest[0], rest[1])] if rest else [
        (os.path.join(ROOT, t), os.path.join(ROOT, m)) for t, m in PAIRS]

    out = ["\u2500\u2500 paper rendering sync (LaTeX source vs Markdown rendering) \u2500\u2500",
           "  A number in one and not the other is drift. Prose divergence must be explained",
           "  by one of the %d artifact classes in ARTIFACT_CLASSES; anything else is drift."
           % len(ARTIFACT_CLASSES),
           ""]
    ck = Checker()
    statuses = []
    for tex_path, md_path in pairs:
        statuses.append(check_pair(out, ck, tex_path, md_path, verbose))

    out.append("\u2500\u2500 artifact classes this gate forgives \u2500\u2500")
    for name, layer, why in ARTIFACT_CLASSES:
        out.append("  %s [%s]" % (pad_t(name, 26), layer))
        for line in wrap(why, 92):
            out.append("      " + line)
    out.append("")

    out.append("\u2500\u2500 CHECKS \u2500\u2500")
    for label, actual, expected, ok in ck.rows:
        if ok:
            out.append("  ok    " + pad_t(label, 70) + actual)
        else:
            out.append("  FAIL  " + pad_t(label, 70) + "got: " + actual
                       + "   expected: " + expected)
    if not ck.rows:
        out.append("  (no pair could be checked)")
    out.append("")

    out.append("\u2500\u2500 WHAT THIS GATE DOES NOT CHECK \u2500\u2500")
    out.append("  Ordering. A paragraph moved from \u00a77 to \u00a78 is invisible here: the segment")
    out.append("  multisets and the number multisets are both order-free. It also does not")
    out.append("  compile the LaTeX, does not check that a cited \u00a7 number resolves to the")
    out.append("  section it claims, and cannot see a number that BOTH sides get wrong.")
    out.append("")

    skipped = statuses.count("skipped")
    drift = statuses.count("drift")
    checked = statuses.count("ok") + drift

    if drift:
        out.append("RESULT: FAIL \u2014 %d of %d checked pair(s) drifted from their LaTeX source."
                   % (drift, checked))
        code = 1
    elif skipped and not allow_skipped:
        out.append("RESULT: CANNOT RUN \u2014 %d pair(s) in sync, %d SKIPPED (a file is missing). "
                   "Re-run with --allow-skipped to treat a missing rendering as advisory."
                   % (checked, skipped))
        code = 2
    elif skipped:
        out.append("RESULT: PASS \u2014 %d pair(s) in sync; %d SKIPPED and NOT checked "
                   "(--allow-skipped)." % (checked, skipped))
        code = 0
    else:
        out.append("RESULT: PASS \u2014 all %d pair(s) in sync with their LaTeX source." % checked)
        code = 0

    sys.stdout.write("\n".join(out) + "\n")
    return code


def wrap(text, width):
    words, line, lines = text.split(), "", []
    for w in words:
        if line and len(line) + 1 + len(w) > width:
            lines.append(line)
            line = w
        else:
            line = (line + " " + w) if line else w
    if line:
        lines.append(line)
    return lines


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except SourceError as exc:
        sys.stderr.write("%s\n" % exc)
        sys.exit(2)
