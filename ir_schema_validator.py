from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SchemaIssue:
    code: str
    message: str
    path: str = ""


@dataclass
class SchemaValidationResult:
    ok: bool
    issues: List[SchemaIssue] = field(default_factory=list)
    patched_ir: Optional[Dict[str, Any]] = None
    patch_actions: List[str] = field(default_factory=list)


class IRSchemaValidator:
    def __init__(
        self,
        allowed_fields: Optional[set[str]] = None,
        allow_unknown_root_keys: bool = True,
        forbid_op_key: bool = True,
    ):
        self.allowed_fields = allowed_fields
        self.allow_unknown_root_keys = allow_unknown_root_keys
        self.forbid_op_key = forbid_op_key

        self.required_root_keys = {"query", "explanation", "warnings"}
        self.allowed_logic_keys = {"and", "or", "not"}
        self.allowed_leaf_keys = {"field", "value"}

    def validate(self, ir: Dict[str, Any], auto_patch: bool = True) -> SchemaValidationResult:
        issues: List[SchemaIssue] = []
        actions: List[str] = []

        if not isinstance(ir, dict):
            return SchemaValidationResult(
                ok=False,
                issues=[SchemaIssue("root_not_object", "Root must be a JSON object", path="$")],
            )

        if not self.allow_unknown_root_keys:
            unknown = [k for k in ir.keys() if k not in self.required_root_keys]
            for k in unknown:
                issues.append(SchemaIssue("unknown_root_key", f"Unknown root key: {k}", path="$"))

        missing = [k for k in self.required_root_keys if k not in ir]
        if missing and auto_patch:
            if "warnings" in missing:
                ir["warnings"] = ""
                actions.append("patch:add_warnings_empty_string")
            if "explanation" in missing:
                ir["explanation"] = ""
                actions.append("patch:add_explanation_empty_string")

        missing2 = [k for k in self.required_root_keys if k not in ir]
        for k in missing2:
            issues.append(SchemaIssue("missing_root_key", f"Missing root key: {k}", path="$"))

        if "explanation" in ir and not isinstance(ir["explanation"], str):
            if auto_patch:
                ir["explanation"] = str(ir["explanation"])
                actions.append("patch:explanation_to_string")
            else:
                issues.append(SchemaIssue("explanation_type", "explanation must be string", path="$.explanation"))

        if "warnings" in ir:
            if isinstance(ir["warnings"], list):
                if auto_patch:
                    ir["warnings"] = "\n".join(str(x) for x in ir["warnings"])
                    actions.append("patch:warnings_list_to_string")
            elif not isinstance(ir["warnings"], str):
                if auto_patch:
                    ir["warnings"] = str(ir["warnings"])
                    actions.append("patch:warnings_to_string")
                else:
                    issues.append(SchemaIssue("warnings_type", "warnings must be string or list", path="$.warnings"))

        query = ir.get("query")
        if not isinstance(query, dict):
            issues.append(SchemaIssue("query_not_object", "query must be a JSON object", path="$.query"))
            return SchemaValidationResult(ok=False, issues=issues, patched_ir=ir, patch_actions=actions)

        node_issues = self._validate_expr(query, "$.query", auto_patch=auto_patch, actions=actions)
        issues.extend(node_issues)

        return SchemaValidationResult(
            ok=(len(issues) == 0),
            issues=issues,
            patched_ir=ir,
            patch_actions=actions,
        )

    def _validate_expr(
        self,
        expr: Any,
        path: str,
        *,
        auto_patch: bool,
        actions: List[str],
    ) -> List[SchemaIssue]:
        issues: List[SchemaIssue] = []

        if not isinstance(expr, dict):
            issues.append(SchemaIssue("expr_not_object", "Expr must be a JSON object", path=path))
            return issues

        if "not" in expr:
            inner = expr["not"]
            issues.extend(self._validate_expr(inner, f"{path}.not", auto_patch=auto_patch, actions=actions))
            return issues

        if "and" in expr:
            items = expr["and"]
            if not isinstance(items, list) or len(items) == 0:
                issues.append(SchemaIssue("and_invalid", "'and' must be a non-empty list", path=f"{path}.and"))
                return issues
            for i, e in enumerate(items):
                issues.extend(self._validate_expr(e, f"{path}.and[{i}]", auto_patch=auto_patch, actions=actions))
            return issues

        if "or" in expr:
            items = expr["or"]
            if not isinstance(items, list) or len(items) == 0:
                issues.append(SchemaIssue("or_invalid", "'or' must be a non-empty list", path=f"{path}.or"))
                return issues
            for i, e in enumerate(items):
                issues.extend(self._validate_expr(e, f"{path}.or[{i}]", auto_patch=auto_patch, actions=actions))
            return issues

        if "field" in expr or "value" in expr:
            if self.forbid_op_key and "op" in expr:
                if auto_patch:
                    expr.pop("op", None)
                    actions.append(f"patch:remove_op@{path}")
                else:
                    issues.append(SchemaIssue("op_forbidden", 'Key "op" is forbidden', path=f"{path}.op"))

            field_v = expr.get("field", None)
            if not isinstance(field_v, str) or not field_v:
                issues.append(SchemaIssue("field_invalid", "Atom field must be a non-empty string", path=f"{path}.field"))
            else:
                if self.allowed_fields is not None and field_v not in self.allowed_fields:
                    issues.append(SchemaIssue("unknown_field", f"Field not allowed: {field_v}", path=f"{path}.field"))

            if "value" not in expr:
                issues.append(SchemaIssue("value_missing", "Atom must contain 'value'", path=f"{path}.value"))

            extra_keys = [k for k in expr.keys() if k not in self.allowed_leaf_keys and k not in {"op"}]
            if extra_keys:
                issues.append(SchemaIssue("atom_extra_keys", f"Unexpected keys in atom: {extra_keys}", path=path))

            return issues

        issues.append(SchemaIssue("unknown_expr_shape", "Unknown expr shape (expected atom/and/or/not)", path=path))
        return issues