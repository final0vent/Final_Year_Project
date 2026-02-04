import pandas as pd
from typing import List, Dict, Any
from rules import RULES


def events_to_df(events: List[Dict[str, Any]]) -> pd.DataFrame:

    if not events:
        return pd.DataFrame()
    return pd.DataFrame(events)


def detect_rule_warnings(df: pd.DataFrame) -> List[Dict[str, Any]]:
    if df.empty or "message" not in df.columns:
        return []

    hits: List[Dict[str, Any]] = []

    for idx, row in df.iterrows():
        msg = str(row.get("message", ""))
        lower_msg = msg.lower()

        for rule in RULES:
            keyword = rule["keyword"].lower()
            if keyword in lower_msg:
                hits.append({
                    "row_index": int(idx),
                    "rule_id": rule["id"],
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "matched_keyword": rule["keyword"],
                    "message": msg,
                    "event_category": row.get("event.category"),
                    "timestamp": row.get("timestamp"),
                })
                break

    return hits


def analyze_events_with_rules(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    df = events_to_df(events)
    warnings = detect_rule_warnings(df)

    return {
        "df": df,
        "warnings": warnings,
        "has_warning": len(warnings) > 0,
    }
