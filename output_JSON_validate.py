import json

def extract_json_candidate(text: str) -> str | None:
    text = text.strip()
    if text.startswith("```"):
        text = text.replace("```json", "").replace("```", "").strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    return text[start:end+1]

def is_valid_json_object(json_text: str) -> tuple[bool, str | None, dict | None]:
    try:
        obj = json.loads(json_text)
        if not isinstance(obj, dict):
            return False, "Root is not a JSON object", None
        return True, None, obj
    except Exception as e:
        return False, str(e), None

raw_output = "...SLM output ..."


if __name__ == "__main__":
    candidate = extract_json_candidate(raw_output)

    if candidate is None:
        print("No JSON object found")
    else:
        ok, err, obj = is_valid_json_object(candidate)
        if ok:
            print("JSON structure valid")
        else:
            print("Invalid JSON:", err)
