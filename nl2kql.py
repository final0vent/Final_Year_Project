from Slm_engine import KQLGeneratorSession
from ir_schema_validator import IRSchemaValidator
from ir_auto_repair import IRAutoRepairEngine

schema_validator = IRSchemaValidator()
kql_session = KQLGeneratorSession()
engine = IRAutoRepairEngine(
    schema_validator=schema_validator,
    kql_session=kql_session,
    max_repairs=2
)

def _kql_escape_value(v):
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return str(v)
    s = str(v).replace('"', '\\"')
    return f'"{s}"'


def generate_kql_from_nl(nl: str, max_new_tokens: int = 1024):
    res = engine.generate_kql_from_nl(nl, max_new_tokens=max_new_tokens)

    timing = res.get("timing", [])
    timing_out = timing[-1] if isinstance(timing, list) and timing else timing

    return {
        "kql": res.get("kql", ""),
        "explanation": res.get("explanation", ""),
        "warnings": res.get("warnings", ""),
        "timing": timing_out,
        "ir": res.get("ir", None),
        "attempts": res.get("attempts", 1),
        "attempt_errors": res.get("attempt_errors", []),
    }