# Copied from hl7_scout/parser.py (2026-11-19) for the "Rejestr HL7" window of
# HospitalHub Portable; keep the two in step by hand.
# Copyright © 2026 Sebastian Bąk. All rights reserved.

import re
from dataclasses import dataclass, field
from typing import List

# Whitelist of standard HL7 v2.x segment names used in fallback line detection
_KNOWN_SEGMENTS = {
    'MSH', 'EVN', 'PID', 'PD1', 'NK1', 'PV1', 'PV2',
    'ORC', 'OBR', 'OBX', 'NTE', 'AL1', 'DG1', 'PR1',
    'MSA', 'ERR', 'IN1', 'IN2', 'IN3', 'GT1', 'SCH',
    'RXO', 'RXE', 'RXD', 'RXA', 'RXR', 'RXC',
    'FT1', 'ACC', 'QRD', 'QRF', 'DSC', 'DSP',
    'SFT', 'UAC', 'SPM', 'SAC', 'BHS', 'BTS', 'FHS', 'FTS',
    'TXA', 'TCD', 'SID', 'IPC', 'BPO', 'BPX', 'BTX',
}

_SEGMENT_NAMES_PATTERN = (
    '|'.join(re.escape(s) for s in sorted(_KNOWN_SEGMENTS, key=len, reverse=True))
    + r'|Z[A-Z0-9]{2}'   # also match Z-segments (ZPI, ZAL, ZPM, etc.)
)

# Primary: segment name at start of string or preceded by non-alpha char
_FALLBACK_RE = re.compile(
    r'(?:^|(?<=[^A-Za-z]))(?:' + _SEGMENT_NAMES_PATTERN + r')\|'
)

# Secondary: for fully concatenated frames where segments follow directly
# after a pipe (e.g. ...value|PID|...), detect segment name right after |
_FALLBACK_AFTER_PIPE_RE = re.compile(
    r'\|(?=' + '(?:' + _SEGMENT_NAMES_PATTERN + r')\|)'
)


def _fallback_split(line: str) -> list:
    """Split a single-line HL7 message by detecting known segment boundaries."""
    # First try primary regex
    matches = list(_FALLBACK_RE.finditer(line))

    if len(matches) <= 1:
        # Try splitting on pipe-before-segment pattern for fully concatenated frames
        # e.g. "...value|PID|..." -> split at | before PID
        split_points = [m.start() for m in _FALLBACK_AFTER_PIPE_RE.finditer(line)]
        if split_points:
            # Also include start if it begins with a segment
            parts = []
            prev = 0
            for sp in split_points:
                chunk = line[prev:sp].strip()
                if chunk:
                    parts.append(chunk)
                prev = sp + 1  # skip the pipe that separates segments
            # Last chunk
            chunk = line[prev:].strip()
            if chunk:
                parts.append(chunk)
            if len(parts) > 1:
                return parts
        return [line]

    parts = []
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(line)
        part = line[start:end].strip()
        if part:
            parts.append(part)
    return parts


@dataclass
class HL7Component:
    raw: str
    subcomponents: List[str]


@dataclass
class HL7Field:
    index: int          # field number per HL7 spec (1-based)
    raw: str
    repetitions: List[List[HL7Component]]   # [rep][component]


@dataclass
class HL7Segment:
    name: str
    raw: str
    fields: List[HL7Field]


@dataclass
class HL7Message:
    segments: List[HL7Segment]
    field_sep: str = '|'
    component_sep: str = '^'
    repetition_sep: str = '~'
    escape_char: str = '\\'
    subcomponent_sep: str = '&'


_PCT_BREAK_RE = re.compile(r'%0[dDaA]')


def url_decode(text: str) -> str:
    """A message copied from AMMS (WYMD_PACZKA.TRESC) is URL-encoded:
    ``%0D`` between the segments, ``%C5%82`` for "ł" — it parsed as one long
    MSH segment (2026-11-19).  Decoded only when it carries an encoded
    segment break, so a plain message with "%" in a value stays as it is."""
    if not _PCT_BREAK_RE.search(text):
        return text
    from urllib.parse import unquote_to_bytes
    raw = unquote_to_bytes(text)
    for enc in ('utf-8', 'cp1250'):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode('latin-1')


def parse(raw: str) -> HL7Message:
    text = url_decode(raw.strip())

    # Normalize all possible segment terminators to \n:
    # \r\n (Windows), \r (HL7 standard CR), \n (Unix),
    # \x0b (VT), \x0c (FF), \x1c (HL7 end-of-block),
    # \u0085 (NEL), \u2028 (line sep), \u2029 (paragraph sep)
    # Replace literal escape sequences (\r, \n, \x0d, \x0a) that appear
    # when copying from databases or logs as visible text
    text = text.replace('\\r\\n', '\n').replace('\\r', '\n').replace('\\n', '\n')
    text = text.replace('\\x0d\\x0a', '\n').replace('\\x0d', '\n').replace('\\x0a', '\n')

    # Normalize all possible segment terminators to \n:
    # \r\n (Windows), \r (HL7 standard CR), \n (Unix),
    # \x0b (VT), \x0c (FF), \x1c (HL7 end-of-block),
    # \u0085 (NEL), \u2028 (line sep), \u2029 (paragraph sep)
    text = re.sub(r'\r\n|\r|\n|\x0b|\x0c|\x1c|\u0085|\u2028|\u2029', '\n', text)
    lines = [l.strip() for l in text.split('\n') if l.strip()]

    # Fallback: if any line contains multiple segments concatenated
    # (e.g. copied from DB as a single string), split on known segment boundaries.
    expanded = []
    for line in lines:
        if '|' in line:
            parts = _fallback_split(line)
            expanded.extend(parts)
        else:
            expanded.append(line)
    lines = expanded

    msg = HL7Message(segments=[])

    if not lines:
        return msg

    # Read delimiters from MSH
    first = lines[0]
    if first.startswith('MSH') and len(first) > 7:
        msg.field_sep = first[3]
        enc = first[4:8]
        msg.component_sep   = enc[0] if len(enc) > 0 else '^'
        msg.repetition_sep  = enc[1] if len(enc) > 1 else '~'
        msg.escape_char     = enc[2] if len(enc) > 2 else '\\'
        msg.subcomponent_sep = enc[3] if len(enc) > 3 else '&'

    for line in lines:
        seg = _parse_segment(line, msg)
        if seg:
            msg.segments.append(seg)

    return msg


def _parse_segment(line: str, msg: HL7Message) -> HL7Segment | None:
    if len(line) < 3:
        return None

    name = line[:3]
    parts = line.split(msg.field_sep)
    fields: List[HL7Field] = []

    for i, raw in enumerate(parts):
        if i == 0:
            # Segment name — not a real field
            continue

        # HL7 field numbering:
        # MSH: parts[1] = MSH-2 (encoding chars), parts[2] = MSH-3, ...
        #      because MSH-1 IS the field separator itself
        # Other: parts[1] = SEG-1, parts[2] = SEG-2, ...
        if name == 'MSH':
            field_num = i + 1
        else:
            field_num = i

        # MSH-1 is the separator char — store as-is
        if name == 'MSH' and field_num == 1:
            fields.append(HL7Field(
                index=1,
                raw=msg.field_sep,
                repetitions=[[HL7Component(raw=msg.field_sep, subcomponents=[msg.field_sep])]]
            ))
            # Also handle the encoding chars (parts[1] = MSH-2)

        repetitions: List[List[HL7Component]] = []
        for rep_raw in raw.split(msg.repetition_sep):
            components: List[HL7Component] = []
            for comp_raw in rep_raw.split(msg.component_sep):
                subcomps = comp_raw.split(msg.subcomponent_sep)
                components.append(HL7Component(raw=comp_raw, subcomponents=subcomps))
            repetitions.append(components)

        fields.append(HL7Field(index=field_num, raw=raw, repetitions=repetitions))

    return HL7Segment(name=name, raw=line, fields=fields)
