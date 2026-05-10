import os
import re
from dataclasses import dataclass, field


_FIELD_SPLIT_RE = re.compile(r"\t+")
_SUPPORTED_TYPES = {
    "string",
    "ustring",
    "byte",
    "ubyte",
    "leshort",
    "uleshort",
    "lelong",
    "ulelong",
    "short",
    "default",
    "name",
    "use",
}


@dataclass
class MagicRule:
    level: int
    offset: int | None
    type_name: str
    mask: int | None
    operator: str | None
    test_value: object
    message: str
    children: list = field(default_factory=list)
    raw_line: str = ""


def _decode_magic_string(value: str) -> bytes:
    text = value.replace(r"\ ", " ")
    return text.encode("latin-1", errors="backslashreplace").decode("unicode_escape").encode("latin-1")


def _decode_message(value: str) -> str:
    return value.encode("latin-1", errors="backslashreplace").decode("unicode_escape")


def _parse_numeric(value: str) -> int:
    text = value.strip()
    if text.startswith("0") and text != "0" and not text.lower().startswith("0x"):
        return int(text, 8)
    return int(text, 0)


def _parse_test(type_name: str, token: str):
    token = token.strip()
    if type_name == "default":
        return None, None
    if type_name in ("name", "use"):
        return None, token
    if token == "x":
        return "x", None

    operator = None
    if token[0] in ("=", "!", ">", "<"):
        operator = token[0]
        token = token[1:]

    if type_name in ("string", "ustring"):
        return operator or "=", _decode_magic_string(token)

    return operator or "=", _parse_numeric(token)


def _read_value(data: bytes, offset: int, type_name: str):
    if offset < 0 or offset >= len(data):
        return None

    if type_name in ("byte", "ubyte"):
        return data[offset]
    if type_name in ("short", "leshort", "uleshort"):
        if offset + 2 > len(data):
            return None
        return int.from_bytes(data[offset:offset + 2], "little", signed=False)
    if type_name in ("lelong", "ulelong"):
        if offset + 4 > len(data):
            return None
        return int.from_bytes(data[offset:offset + 4], "little", signed=False)
    return None


def _apply_mask(value, mask):
    if value is None or mask is None:
        return value
    if isinstance(value, (bytes, bytearray)):
        return value
    return value & mask


def _compare_value(actual, operator, expected):
    if operator == "x":
        return True
    if actual is None:
        return False
    if operator in (None, "="):
        return actual == expected
    if operator == "!":
        return actual != expected
    if operator == ">":
        return actual > expected
    if operator == "<":
        return actual < expected
    return False


def _render_message(message: str, actual):
    if not message:
        return None
    if "%" not in message:
        return message
    if actual is None:
        return message

    value = actual
    if isinstance(actual, (bytes, bytearray)):
        value = actual.split(b"\x00", 1)[0].decode("latin-1", errors="replace")

    try:
        return message % value
    except (TypeError, ValueError):
        return message


class VendoredMagicEngine:
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        self._loaded = False
        self.root_rules = []
        self.named_rules = {}

    def _load(self):
        if self._loaded:
            return
        self._loaded = True

        wanted_files = ("compress", "archive", "linux")
        top_level = []
        named = {}

        for file_name in wanted_files:
            path = os.path.join(self.base_dir, "Magdir", file_name)
            if not os.path.exists(path):
                continue
            with open(path, "r", encoding="utf-8", errors="replace") as fp:
                rules = self._parse_rules(fp.readlines())
            top_level.extend(rules["root"])
            named.update(rules["named"])

        self.root_rules = top_level
        self.named_rules = named

    def _parse_rules(self, lines: list[str]):
        root = []
        named = {}
        stack = []

        for raw in lines:
            line = raw.rstrip("\r\n")
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("!:"):
                continue

            level = 0
            while level < len(line) and line[level] == ">":
                level += 1
            body = line[level:].strip()
            if not body:
                continue

            parts = [part for part in _FIELD_SPLIT_RE.split(body) if part != ""]
            if len(parts) < 3:
                continue

            offset_token, type_token, test_token = parts[:3]
            message = parts[3] if len(parts) > 3 else ""

            if not re.fullmatch(r"(0x[0-9a-fA-F]+|\d+)", offset_token):
                continue
            if "(" in offset_token or "&" in offset_token:
                continue

            offset = _parse_numeric(offset_token)
            mask = None
            type_name = type_token
            if "&" in type_token:
                type_name, mask_token = type_token.split("&", 1)
                if "(" in mask_token or "." in mask_token or " " in mask_token or "\t" in mask_token:
                    continue
                try:
                    mask = _parse_numeric(mask_token)
                except ValueError:
                    continue

            if type_name not in _SUPPORTED_TYPES:
                continue

            try:
                operator, test_value = _parse_test(type_name, test_token)
            except (ValueError, UnicodeDecodeError):
                continue
            rule = MagicRule(
                level=level,
                offset=offset,
                type_name=type_name,
                mask=mask,
                operator=operator,
                test_value=test_value,
                message=_decode_message(message),
                raw_line=line,
            )

            while stack and stack[-1].level >= level:
                stack.pop()

            if stack:
                stack[-1].children.append(rule)
            else:
                if type_name == "name":
                    named[str(test_value)] = rule
                else:
                    root.append(rule)

            stack.append(rule)

        return {"root": root, "named": named}

    def describe(self, data: bytes):
        self._load()
        for rule in self.root_rules:
            rendered = self._eval_rule(rule, data, active_uses=set())
            if rendered:
                return rendered
        return None

    def _eval_rule(self, rule: MagicRule, data: bytes, active_uses: set[str]):
        matched, actual = self._match_rule(rule, data)
        if not matched:
            return None

        parts = []
        if rule.message:
            parts.append(_render_message(rule.message, actual))

        for child in rule.children:
            rendered = self._eval_child(child, data, active_uses)
            if rendered:
                parts.append(rendered)

        if not parts:
            return None
        return self._join_parts(parts)

    def _eval_child(self, rule: MagicRule, data: bytes, active_uses: set[str]):
        matched, actual = self._match_rule(rule, data)
        if not matched:
            return None

        if rule.type_name == "use":
            use_name = str(rule.test_value)
            if use_name in active_uses:
                return None

            named = self.named_rules.get(use_name)
            if named is None:
                return None
            rendered_children = []
            next_active = set(active_uses)
            next_active.add(use_name)
            for child in named.children:
                rendered = self._eval_child(child, data, next_active)
                if rendered:
                    rendered_children.append(rendered)
            return self._join_parts(rendered_children) if rendered_children else None

        parts = []
        if rule.message:
            parts.append(_render_message(rule.message, actual))
        for child in rule.children:
            rendered = self._eval_child(child, data, active_uses)
            if rendered:
                parts.append(rendered)
        return self._join_parts(parts) if parts else None

    def _match_rule(self, rule: MagicRule, data: bytes):
        if rule.type_name == "default":
            return True, None
        if rule.type_name == "use":
            return True, None
        if rule.type_name == "name":
            return False, None

        if rule.type_name in ("string", "ustring"):
            expected = rule.test_value
            offset = rule.offset or 0
            if offset + len(expected) > len(data):
                return False, None
            actual = data[offset:offset + len(expected)]
            if rule.operator == ">":
                if expected == b"\x00":
                    return actual[:1] > b"\x00", actual
                return actual > expected, actual
            if rule.operator == "!":
                return actual != expected, actual
            return actual == expected, actual

        actual = _read_value(data, rule.offset or 0, rule.type_name)
        actual = _apply_mask(actual, rule.mask)
        return _compare_value(actual, rule.operator, rule.test_value), actual

    def _join_parts(self, parts: list[str]):
        if not parts:
            return None
        rendered = ""
        for part in parts:
            if not part:
                continue
            if part.startswith("\b"):
                rendered += part[1:]
            elif not rendered:
                rendered = part
            else:
                rendered += " " + part
        return rendered or None
