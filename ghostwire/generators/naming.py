"""Identifier sanitization helpers shared by the code generators.
Captured parameter names (e.g. 'filter[status]', 'page.size', 'from') are not always valid identifiers.
"""

import keyword
import re
from typing import Iterable, Set

# Names the generated Python methods already use internally, plus builtins/imports a parameter could shadow
PYTHON_RESERVED = set(keyword.kwlist) | {
    "self", "payload", "params", "endpoint_path", "response", "variables", "body", "match", "case", "type",
    "str", "quote", "os", "httpx", "Any", "Dict", "List", "Optional", "Union",
}

TYPESCRIPT_RESERVED = {
    "break", "case", "catch", "class", "const", "continue", "debugger", "default", "delete", "do", "else",
    "enum", "export", "extends", "false", "finally", "for", "function", "if", "import", "in", "instanceof",
    "new", "null", "return", "super", "switch", "this", "throw", "true", "try", "typeof", "var", "void",
    "while", "with", "let", "static", "yield", "await", "implements", "interface", "package", "private",
    "protected", "public", "payload", "params", "variables", "endpoint",
    "encodeURIComponent", "String", "JSON", "URLSearchParams", "FormData", "Object", "fetch", "Record",
}


def _unique(name: str, taken: Set[str], separator: str) -> str:
    final = name
    counter = 1
    while final in taken:
        final = f"{name}{separator}{counter}"
        counter += 1
    taken.add(final)
    return final


def python_identifier(name: str, taken: Set[str]) -> str:
    """Converts a raw name to a unique, valid Python identifier and records it in `taken`."""
    ident = re.sub(r"[^a-zA-Z0-9_]", "_", name).strip("_") or "param"
    ident = re.sub(r"_+", "_", ident)
    if ident[0].isdigit():
        ident = f"_{ident}"
    if ident in PYTHON_RESERVED:
        ident = f"{ident}_"
    return _unique(ident, taken, "_")


def typescript_identifier(name: str, taken: Set[str]) -> str:
    """Converts a raw name to a unique, valid camelCase TypeScript identifier and records it in `taken`."""
    parts = [p for p in re.split(r"[^a-zA-Z0-9]+", name) if p]
    if not parts:
        parts = ["param"]
    ident = parts[0][0].lower() + parts[0][1:] + "".join(p[0].upper() + p[1:] for p in parts[1:])
    if ident[0].isdigit():
        ident = f"_{ident}"
    if ident in TYPESCRIPT_RESERVED:
        ident = f"{ident}_"
    return _unique(ident, taken, "")


def python_doc_text(text: str) -> str:
    """Makes captured text safe inside a generated triple-quoted docstring."""
    text = re.sub(r"[\r\n\t]+", " ", text)
    return text.replace("\\", "\\\\").replace('"""', '\\"\\"\\"')


def ts_comment_text(text: str) -> str:
    """Makes captured text safe inside a generated /** ... */ comment."""
    return re.sub(r"[\r\n\t]+", " ", text).replace("*/", "*\\/")


def path_segments(path: str) -> Iterable[str]:
    """Splits an endpoint template ('/users/{userId}/posts') into its segments, keeping braces."""
    return re.split(r"(\{[^}]+\})", path)
