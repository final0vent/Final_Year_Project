# kql_parser.py

import re
from typing import List, Tuple, Dict, Any


def tokenize_kql(query: str) -> List[str]:
    """
    Split the KQL string into tokens.
    From
      event.category:"process start" and severity:high
    to
      ['event.category:"process start"', 'and', 'severity:high']
    """
    pattern = r'([\w\.-]+:"[^"]*")|(\S+)'
    tokens = []
    for m in re.finditer(pattern, query):
        token = m.group(1) or m.group(2)
        tokens.append(token)
    return tokens


def parse_kql_conditions(tokens: List[str]) -> Tuple[List[Tuple[str, str]], List[str]]:
    """
    simplified syntax:
      term (AND/OR term)

    Example forms:
      field:value
      field:"value with spaces"
      freeTextWithoutField   (if there's no colon, treat it as a full-text search on _all)

    Returns:
      conditions: [(field, value), ...]
      operators:  ['and' | 'or', ...]  length = len(conditions) - 1
    """

    conditions: List[Tuple[str, str]] = []
    operators: List[str] = []

    for token in tokens:
        low = token.lower()
        if low in ("and", "or"):
            operators.append(low)
            continue

        if ":" in token:
            field, val = token.split(":", 1)
            field = field.strip()
            val = val.strip()
            if val.startswith('"') and val.endswith('"'):
                val = val[1:-1]
            conditions.append((field, val))
        else:
            conditions.append(("_all", token))

    if len(operators) != max(0, len(conditions) - 1):
        operators = ["and"] * max(0, len(conditions) - 1)

    return conditions, operators


def event_matches_condition(event: Dict[str, Any], cond: Tuple[str, str]) -> bool:
    """
    Determine whether a single event satisfies a condition (field, value).

    Examples:
      - Specific field, e.g. "source.ip", "event.category"
      - "_all": perform a fuzzy match across all fields (including structured-data)
    """
    field, value = cond
    value = str(value).lower()

    if field == "_all":
        for k, v in event.items():
            if k == "structured":
                continue
            if v is None:
                continue
            if value in str(v).lower():
                return True

        sd = event.get("structured") or {}
        for v in sd.values():
            if v is None:
                continue
            if value in str(v).lower():
                return True

        return False

    v = event.get(field)

    if v is None and "." in field:
        alt = field.replace(".", "_")
        v = event.get(alt)

    if v is None:
        sd = event.get("structured") or {}
        if field in sd:
            v = sd[field]

    if v is None:
        return False

    return value in str(v).lower()


def filter_events_by_kql(events: List[Dict[str, Any]], query: str) -> List[Dict[str, Any]]:
    """
    Filter a list of events based on a KQL query.

    Supported syntax examples:
      - field:value
      - field:"value with spaces"
      - Logical connectors: AND / OR (case-insensitive)
      - Free text: if no colon is present, automatically treated as a search across all fields (_all)

    Not supported examples:
      - Parentheses ()
      - NOT / !
      - Comparison operators > < >= <=
      - Wildcards (*, ?), regular expressions, etc.
    """

    query = (query or "").strip()
    if not query:
        return events

    tokens = tokenize_kql(query)
    if not tokens:
        return events

    conditions, operators = parse_kql_conditions(tokens)
    if not conditions:
        return events

    filtered: List[Dict[str, Any]] = []

    for ev in events:
        result = event_matches_condition(ev, conditions[0])

        for op, cond in zip(operators, conditions[1:]):
            if op == "and":
                result = result and event_matches_condition(ev, cond)
            else:  # "or"
                result = result or event_matches_condition(ev, cond)

        if result:
            filtered.append(ev)

    return filtered
