"""Small lexical comment filter, not a language parser."""

import re

MARKER = re.compile(r"\bcodeshield:\s*test-fixture\b", re.I)
PLACEHOLDER = re.compile(
    r"(?i)^(?:your[_-].*|(?:example|dummy|placeholder)(?:[_-].*)?|(?:changeme|replace[_-]?me|"
    r"demo_secret_value_replace_me)|<[^>]+>|\$\{[^}]+\}|%[A-Z_]+%)$"
)
HASH_OR_UUID = re.compile(r"(?i)^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|"
                          r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})$")


def is_placeholder(value: str) -> bool:
    return value == "AKIAIOSFODNN7EXAMPLE" or bool(PLACEHOLDER.fullmatch(value))


def is_reference(value: str) -> bool:
    return bool(re.match(r"(?:os\.(?:environ|getenv)|process\.env|(?:getenv|env|config)\(|"
                         r"\$\{|\$\(|None\b|null\b|true\b|false\b)", value))


def code_lines(text: str, path: str) -> list[str]:
    """Preserve offsets, remove comments and standalone Python triple docstrings.

    Context is built from the complete snapshot, including unchanged lines.
    Only a marker inside a comment suppresses the marked line.
    """
    python = path.lower().endswith(".py")
    slash_comments = path.lower().endswith((".js", ".cjs", ".mjs", ".jsx", ".ts", ".tsx", ".json"))
    quote = ""
    block = False
    docstring = False
    output = []
    for line in text.split("\n"):
        chars = list(line)
        comments = []
        i = 0
        while i < len(line):
            if block:
                end = line.find("*/", i)
                stop = len(line) if end < 0 else end + 2
                comments.append(line[i:stop])
                chars[i:stop] = " " * (stop - i)
                i = stop
                if end >= 0:
                    block = False
                continue
            if quote:
                if line.startswith(quote, i):
                    if docstring:
                        chars[i:i + len(quote)] = " " * len(quote)
                    i += len(quote)
                    quote = ""
                    docstring = False
                elif line[i] == "\\":
                    if docstring:
                        chars[i:i + 2] = " " * len(line[i:i + 2])
                    i += 2
                else:
                    if docstring:
                        chars[i] = " "
                    i += 1
                continue
            if ((slash_comments and line.startswith("//", i)) or
                    (not slash_comments and line[i] == "#" and (python or i == 0 or line[i - 1].isspace()))):
                comments.append(line[i:])
                chars[i:] = " " * (len(line) - i)
                break
            if slash_comments and line.startswith("/*", i):
                block = True
                continue
            if line[i] in "\"'`":
                quote = line[i]
                if python and line.startswith(quote * 3, i):
                    quote *= 3
                    docstring = line[:i].strip().lower() in ("", "r", "u")
                if docstring:
                    chars[i:i + len(quote)] = " " * len(quote)
                i += len(quote)
                continue
            i += 1
        output.append(" " * len(line) if any(MARKER.search(c) for c in comments) else "".join(chars))
        # Ordinary Python/JSON strings cannot cross a physical newline unless escaped.
        if quote and len(quote) == 1 and quote != "`" and not line.endswith("\\"):
            quote = ""
    return output
