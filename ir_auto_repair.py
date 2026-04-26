from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from Slm_engine import KQLGeneratorSession
from output_JSON_validate import extract_json_candidate, is_valid_json_object
from ir_schema_validator import IRSchemaValidator


def _kql_escape_value(v: Any) -> str:
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return str(v)
    s = str(v).replace('"', '\\"')
    return f'"{s}"'


def _compile_atom(atom: dict) -> str:
    field = atom.get("field")
    if not field:
        raise ValueError("Atom missing 'field'")

    if "value" not in atom:
        raise ValueError("Atom missing 'value'")

    value = atom.get("value", "")
    return f"{field}:{_kql_escape_value(value)}"


def _compile_expr(expr: dict) -> str:
    if not isinstance(expr, dict):
        raise ValueError("Expr must be a JSON object")

    if "and" in expr:
        items = expr["and"]
        if not isinstance(items, list) or len(items) == 0:
            raise ValueError("'and' must be a non-empty list")
        compiled = [_compile_expr(e) for e in items]
        if len(compiled) == 1:
            return compiled[0]
        return " AND ".join(compiled)

    if "or" in expr:
        items = expr["or"]
        if not isinstance(items, list) or len(items) == 0:
            raise ValueError("'or' must be a non-empty list")
        compiled = [_compile_expr(e) for e in items]
        if len(compiled) == 1:
            return compiled[0]
        return " OR ".join(compiled)

    # atom must have BOTH field and value
    if "field" in expr and "value" in expr:
        return _compile_atom(expr)

    raise ValueError("Unknown expr shape (expected atom(field/value)/and/or/not)")


def compile_grouped_ir_to_kql(ir: dict) -> str:
    query = ir.get("query")
    if not isinstance(query, dict):
        raise ValueError("IR missing 'query' object")
    return _compile_expr(query)

@dataclass
class AttemptInfo:
    attempt: int
    error: str
    raw_output: str


class IRAutoRepairEngine:
    def __init__(
        self,
        schema_validator: Optional[IRSchemaValidator] = None,
        kql_session: Optional[KQLGeneratorSession] = None,
        max_repairs: int = 2,
    ) -> None:
        self.schema_validator = schema_validator or IRSchemaValidator()
        self.kql_session = kql_session or KQLGeneratorSession()
        self.max_repairs = max_repairs

    def _build_initial_prompt(self, nl: str) -> str:
        return nl

    def _build_repair_prompt(self, nl: str, prev_output: str, error_msg: str) -> str:
        return (
            "You are repairing an invalid IR JSON output.\n"
            "Output ONLY a single JSON object. No markdown fences. No extra text.\n"
            "Keep EXACTLY the same meaning as the user's request. Do NOT add/drop constraints.\n"
            "\n"
            "IR rules:\n"
            "- Root keys must include: query, explanation, warnings.\n"
            "- query must be a JSON object.\n"
            "- Expression nodes must be one of:\n"
            "  * atom: {\"field\": <string>, \"value\": <any>}\n"
            "  * and:  {\"and\": [<expr>, ...]}\n"
            "  * or:   {\"or\":  [<expr>, ...]}\n"
            "  * not:  {\"not\": <expr>}\n"
            "- 'and' and 'or' must be NON-EMPTY lists.\n"
            "\n"
            f"User request (NL): {nl}\n"
            f"Validation/compile error: {error_msg}\n"
            "\n"
            "Previous model output:\n"
            f"{prev_output}\n"
            "\n"
            "Repaired JSON:\n"
        )

    def _parse_validate_schema_compile(self, raw: str) -> Tuple[dict, str]:
        raw = (raw or "").strip()
        candidate = extract_json_candidate(raw)

        ok, err, ir = is_valid_json_object(candidate)
        if not ok or ir is None:
            raise ValueError(f"Invalid JSON structure: {err}")

        schema_res = self.schema_validator.validate(ir, auto_patch=True)
        if not schema_res.ok:
            msgs = "; ".join([f"{i.code}@{i.path}:{i.message}" for i in schema_res.issues])
            raise ValueError(f"Schema validation failed: {msgs}")

        patched_ir = schema_res.patched_ir or ir
        kql = compile_grouped_ir_to_kql(patched_ir).strip()

        return patched_ir, kql

    def generate_kql_from_nl(self, nl: str, max_new_tokens: int = 256) -> Dict[str, Any]:
        prompt = self._build_initial_prompt(nl)

        attempt_errors: List[AttemptInfo] = []
        timings: List[Any] = []

        total_attempts = 1 + int(self.max_repairs)

        last_ir: Optional[dict] = None
        last_raw: str = ""
        last_err: str = ""

        for attempt in range(1, total_attempts + 1):
            raw, timing = self.kql_session.generate(prompt, max_new_tokens=max_new_tokens)
            timings.append(timing)
            last_raw = (raw or "").strip()

            try:
                patched_ir, kql = self._parse_validate_schema_compile(last_raw)
                last_ir = patched_ir

                explanation = (patched_ir.get("explanation", "") or "").strip()
                warnings = (patched_ir.get("warnings", "") or "").strip()

                return {
                    "kql": kql,
                    "ir": patched_ir,
                    "explanation": explanation,
                    "warnings": warnings,
                    "attempts": attempt,
                    "attempt_errors": attempt_errors,
                    "timing": timings,
                }

            except Exception as e:
                last_err = str(e)
                attempt_errors.append(AttemptInfo(attempt=attempt, error=last_err, raw_output=last_raw))

                if attempt >= total_attempts:
                    return {
                        "kql": "",
                        "ir": last_ir,
                        "explanation": f"IR parsing/compile failed. Error: {last_err}\nOriginal model output:\n{last_raw}",
                        "warnings": "Auto-repair stopped (max retries reached). Check the SLM output or schema rules.",
                        "attempts": attempt,
                        "attempt_errors": attempt_errors,
                        "timing": timings,
                    }

                prompt = self._build_repair_prompt(nl=nl, prev_output=last_raw, error_msg=last_err)

        return {
            "kql": "",
            "ir": last_ir,
            "explanation": f"IR parsing/compile failed. Error: {last_err}\nOriginal model output:\n{last_raw}",
            "warnings": "Auto-repair stopped.",
            "attempts": total_attempts,
            "attempt_errors": attempt_errors,
            "timing": timings,
        }
