"""Minimal byte-range plans with structural proof; sensitive state stays in memory."""

import ast
import os
import re
import tokenize
import io
from dataclasses import dataclass, field

from codeshield.agent.providers import in_ci
from codeshield.config import Config, ConfigError
from codeshield.errors import ScanError
from codeshield.git_diff import Git, parse_changes
from codeshield.models import Classification, Finding, Provider
from codeshield.remediation.framework import identify
from codeshield.remediation.snapshot import Snapshot
from codeshield.remediation.validator import javascript_tree, syntax
from codeshield.scanner import scan
from codeshield.detectors.patterns import PREFIXES


def index_equivalent(working: bytes | None, staged: bytes) -> bool:
    # Git may normalize CRLF in the index; use working bytes for the minimal edit.
    return working is not None and working.replace(b"\r\n", b"\n") == staged.replace(b"\r\n", b"\n")


@dataclass(frozen=True, repr=False)
class Edit:
    before: Snapshot
    after: bytes = field(repr=False)
    private: bool = False


@dataclass(frozen=True, repr=False)
class Plan:
    git: Git
    config: Config
    finding: Finding
    runtime: str
    env_name: str
    edits: tuple[Edit, ...] = field(repr=False)
    guards: dict[str, Snapshot] = field(repr=False)
    index: bytes = field(repr=False)
    head: bytes = field(repr=False)
    adds_import: bool = False
    states: tuple[str, ...] = ("finding", "assess_finding", "choose_policy", "propose_fix", "validate_fix", "await_approval")

    def preview(self) -> str:
        expression = f'os.environ["{self.env_name}"]' if self.runtime == "python" else f"process.env.{self.env_name}"
        lines = [f"Finding: {self.finding.finding_id}; runtime: {self.runtime}",
                 f"--- {self.finding.path} (staged snapshot)", f"+++ {self.finding.path} (proposed worktree)",
                 f"@@ line {self.finding.line}; sanitized structural diff @@",
                 '- <credential_identifier> = "<REDACTED_SECRET>"', f"+ <credential_identifier> = {expression}"]
        if self.runtime == "python":
            lines.append("+ import os" if self.adds_import else "Reuses the existing import os.")
        for edit in self.edits:
            if edit.before.relative == ".gitignore":
                for rule in edit.after[len(edit.before.data or b""):].splitlines():
                    if rule in (b"/.env", b"/.codeshield/"):
                        lines.append("+ .gitignore: " + rule.decode())
            elif edit.before.relative == ".env.example":
                lines.append(f"+ .env.example: {self.env_name}=")
            elif edit.before.relative == ".env":
                lines.append(f"+ .env: {self.env_name}=<REDACTED_SECRET> (explicit --store-secret consent)")
        lines.extend(("No Git staging/commit/push is performed. The index will still require review and restaging.",
                      "Configure the environment in your application startup; this patch does not add a dotenv loader.",
                      "Rotate/revoke any credential previously committed, pushed, or otherwise exposed."))
        return "\n".join(lines) + "\n"


def binding_names(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            yield node.id
        elif isinstance(node, ast.arg):
            yield node.arg
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                yield alias.asname or alias.name.split(".")[0]
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            yield node.name
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
            yield node.name
        elif isinstance(node, ast.MatchMapping) and node.rest:
            yield node.rest


def python_span(data: bytes, line: int, value: str):
    bom = 3 if data.startswith(b"\xef\xbb\xbf") else 0
    payload = data[bom:]
    tree = ast.parse(payload)
    matches = []
    for statement in tree.body:
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target = statement.targets[0]
        elif isinstance(statement, ast.AnnAssign):
            target = statement.target
        else:
            continue
        literal = statement.value
        if (isinstance(target, ast.Name) and isinstance(literal, ast.Constant) and isinstance(literal.value, str)
                and statement.lineno == line == literal.lineno == literal.end_lineno == statement.end_lineno
                and literal.value == value and statement.col_offset == 0):
            matches.append((statement, target, literal))
    if len(matches) != 1:
        raise ScanError("Only an unambiguous, single-line module-level string assignment can be fixed.")
    statement, target, literal = matches[0]
    if sum(node.lineno == line for node in tree.body) != 1:
        raise ScanError("Multiple statements on the target line require manual remediation.")
    names = list(binding_names(tree))
    if names.count(target.id) != 1 or target.id.startswith("__"):
        raise ScanError("Ambiguous or repeated variable bindings prevent automatic remediation.")
    imports = [node for node in tree.body if isinstance(node, ast.Import)
               for alias in node.names if alias.name == "os" and alias.asname is None]
    if names.count("os") != len(imports):
        raise ScanError("The os binding is shadowed or ambiguous.")
    for node in ast.walk(tree):
        if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)):
            root = node
            while isinstance(root, (ast.Attribute, ast.Subscript)):
                root = root.value
            if isinstance(root, ast.Name) and root.id == "os":
                raise ScanError("Mutated os attributes prevent safe environment access.")
    if any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in
           {"exec", "eval", "globals", "locals", "__import__", "setattr", "delattr"} for n in ast.walk(tree)):
        raise ScanError("Dynamic namespace mutation prevents a safe environment replacement.")
    lines = payload.split(b"\n")
    start = bom + sum(len(part) + 1 for part in lines[:line - 1]) + literal.col_offset
    end = bom + sum(len(part) + 1 for part in lines[:line - 1]) + literal.end_col_offset
    token = data[start:end]
    if (not re.fullmatch(rb'''(?:"[^"\\\r\n]*"|'[^'\\\r\n]*')''', token)
            or len([t for t in tokenize.generate_tokens(io.StringIO(token.decode("utf-8")).readline) if t.type == tokenize.STRING]) != 1):
        raise ScanError("Escaped, concatenated, prefixed or multiline strings require manual remediation.")
    return target.id, start, end, not any(node.lineno < line for node in imports), bom + sum(len(part) + 1 for part in lines[:line - 1])


def walk_js(node):
    yield node
    for child in node.named_children:
        yield from walk_js(child)


def node_span(data: bytes, line: int, value: str):
    tree = javascript_tree(data)
    matches = []
    for statement in tree.named_children:
        if statement.type not in ("lexical_declaration", "variable_declaration"):
            continue
        declarations = [child for child in statement.named_children if child.type != "comment"]
        if len(declarations) != 1 or declarations[0].type != "variable_declarator":
            continue
        declaration = declarations[0]
        name, literal = declaration.child_by_field_name("name"), declaration.child_by_field_name("value")
        if (name is not None and literal is not None and name.type == "identifier" and literal.type == "string"
                and statement.start_point.row + 1 == line == literal.start_point.row + 1 == literal.end_point.row + 1
                and literal.text[1:-1].decode("utf-8") == value and b"\\" not in literal.text):
            matches.append((statement, name, literal))
    if len(matches) != 1:
        raise ScanError("Only a single top-level Node.js declaration with a plain string literal is eligible.")
    statement, name, literal = matches[0]
    if sum(n.start_point.row + 1 == line and n.type != "comment" for n in tree.named_children) != 1:
        raise ScanError("Multiple statements on the target line require manual remediation.")
    target = name.text
    bindings = 0
    for node in walk_js(tree):
        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            if left and any(child.type == "identifier" and child.text == b"process" for child in walk_js(left)):
                raise ScanError("Mutating process bindings prevents automatic remediation.")
        if node.type in ("shorthand_property_identifier_pattern", "shorthand_property_identifier", "property_identifier") and node.text == b"process":
            raise ScanError("Ambiguous process bindings require manual remediation.")
        if node.type != "identifier":
            continue
        if node.text in (b"global", b"globalThis", b"eval", b"Function", b"Proxy", b"Reflect"):
            raise ScanError("Dynamic global bindings prevent automatic remediation.")
        parent = node.parent
        if node.text == b"process":
            if parent.type != "member_expression" or parent.child_by_field_name("object") != node:
                raise ScanError("Node.js process is shadowed or used ambiguously.")
            if parent.parent and parent.parent.type == "assignment_expression" and parent.parent.child_by_field_name("left") == parent:
                raise ScanError("Mutating process bindings prevents automatic remediation.")
        if node.text == target:
            if ((parent.type == "variable_declarator" and parent.child_by_field_name("name") == node)
                    or parent.type in ("formal_parameters", "required_parameter", "import_clause", "import_specifier")
                    or (parent.type == "assignment_expression" and parent.child_by_field_name("left") == node)
                    or parent.type == "update_expression"):
                bindings += 1
    if bindings != 1 or target == b"process":
        raise ScanError("Ambiguous or repeated JavaScript bindings require manual remediation.")
    return target.decode("ascii"), literal.start_byte, literal.end_byte, False, 0


def environment_name(identifier: str, proposed: str | None, secret: str) -> str:
    name = proposed or re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", identifier).upper()
    if (not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", name) or name.startswith(("VITE_", "NEXT_PUBLIC_", "REACT_APP_", "PUBLIC_"))
            or name in {"PATH", "NODE_OPTIONS", "NODE_PATH", "PYTHONPATH", "PYTHONHOME", "LD_PRELOAD", "LD_LIBRARY_PATH"}
            or secret in name or any(pattern.search(name, timeout=0.05) for _, pattern, _ in PREFIXES)):
        raise ScanError("Destination environment variable is unsafe or invalid.")
    if name in os.environ and os.environ[name] != secret:
        raise ScanError("The destination environment variable already has a different process value.")
    return name


def append_line(data: bytes | None, line: bytes) -> bytes:
    data = data or b""
    newline = b"\r\n" if b"\r\n" in data else b"\n"
    return data + (newline if data and not data.endswith(b"\n") else b"") + line + newline


def entries(data: bytes | None):
    try:
        return re.findall(r"(?m)^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=([^\r\n]*)", (data or b"").decode("utf-8-sig"))
    except UnicodeError:
        raise ScanError("Environment metadata must be UTF-8 text.") from None


def is_ignored(git: Git, relative: str) -> bool:
    output = git.run("check-ignore", "--no-index", "--non-matching", "--verbose", "--stdin", "-z",
                     input=relative.encode() + b"\0", accepted_codes=(0, 1))
    fields = output.split(b"\0")
    if len(fields) != 5 or fields[3] != relative.encode():
        raise ScanError("Git ignore rules could not be verified.")
    return bool(fields[2]) and not fields[2].startswith(b"!")


def validate_dotenv(data: bytes | None):
    try:
        for line in (data or b"").decode("utf-8-sig").splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if not re.fullmatch(r'''\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*(?:"[^"\\]*"|'[^'\\]*'|[^\s#'"\\]*)\s*(?:#.*)?''', line):
                raise ScanError("Complex or invalid dotenv syntax requires manual environment-file handling.")
    except UnicodeError:
        raise ScanError("Environment metadata must be UTF-8 text.") from None


def plan_remediation(finding_id: str, config: Config, *, cwd=None, env_name: str | None = None, store_secret: bool = False) -> Plan:
    if not re.fullmatch("[0-9a-f]{24}", finding_id):
        raise ConfigError("Finding ID must be the 24-character ID from a fresh staged scan.")
    if config.provider == Provider.GEMINI:
        raise ConfigError("Fix planning uses offline deterministic proof; select --provider mock or rules. Gemini verification remains an explicit scan operation.")
    if in_ci():
        raise ScanError("Remediation is disabled in CI.")
    from pathlib import Path
    git = Git(cwd or Path.cwd(), config)
    index, head = git.run("ls-files", "--stage", "-z"), git.run("rev-parse", "--revs-only", "HEAD")
    tracked = {}
    for row in index.split(b"\0"):
        if row:
            header, raw_path = row.split(b"\t", 1)
            tracked[raw_path.decode("utf-8")] = header.split()
    if ".env" in tracked:
        raise ScanError("Tracked .env files cannot receive credentials; untrack them and review exposure first.")
    selected = []

    def collect(finding, relative, data, candidate):
        if finding.finding_id == finding_id:
            selected.append((relative, data, candidate))

    result = scan(config, cwd=git.root, _on_finding=collect)
    findings = [item for item in result.findings if item.finding_id == finding_id]
    if len(findings) != 1 or len(selected) != 1:
        raise ScanError("Finding is absent or stale; rerun the staged scan.")
    finding = findings[0]
    if (finding.verification.status != "ok" or finding.verification.decision.classification != Classification.LIKELY_SECRET
            or finding.rule_id == "high-entropy-secret"):
        raise ScanError("Uncertain, false-positive or failed verification cannot authorize remediation.")
    relative, data, candidate = selected[0]
    guards = {}

    def read(name):
        if name not in guards:
            guards[name] = Snapshot.read(git.root, name, config.max_file_bytes)
            if name in tracked:
                mode, oid, stage = tracked[name]
                if (mode not in (b"100644", b"100755") or stage != b"0" or guards[name].data is None
                        or git.blob_size(oid.decode()) > config.max_file_bytes
                        or not index_equivalent(guards[name].data, git.run("cat-file", "blob", oid.decode(), limit=config.max_file_bytes))):
                    raise ScanError("Inspected source or configuration has unstaged changes or unsafe tracking state.")
            elif name.endswith("package.json") and guards[name].data is not None:
                raise ScanError("Stage framework metadata intentionally before remediation planning.")
        return guards[name]

    source = read(relative)
    source.writable()
    if not index_equivalent(source.data, data):
        raise ScanError("The target has unstaged changes; review and stage intentionally before fixing.")
    data = source.data
    changes = [c for c in parse_changes(git.staged_metadata()) if c.path == relative]
    if (len(changes) != 1 or changes[0].old_path != relative
            or changes[0].mode not in ("100644", "100755") or changes[0].old_mode not in ("000000", "100644", "100755")):
        raise ScanError("Renames, type changes or untracked targets require manual remediation.")
    runtime = identify(relative, data, read)
    if runtime == "python" and read("os.py").data is not None:
        raise ScanError("A local os module makes environment access ambiguous.")
    syntax(data, runtime, git.root, config.git_timeout_seconds)
    identifier, start, end, add_import, insert_at = (python_span if runtime == "python" else node_span)(data, finding.line, candidate.value)
    name = environment_name(identifier, env_name, candidate.value)
    expression = f'os.environ["{name}"]'.encode() if runtime == "python" else f"process.env.{name}".encode()
    after = data[:start] + expression + data[end:]
    if add_import:
        after = after[:insert_at] + b"import os" + (b"\r\n" if b"\r\n" in data else b"\n") + after[insert_at:]
    syntax(after, runtime, git.root, config.git_timeout_seconds)
    edits = []
    environment = read(".env")
    if b".env" in git.run("ls-files", "-z", "--", ".env").split(b"\0"):
        raise ScanError("Tracked .env files cannot receive credentials; untrack them and review exposure first.")
    if name in dict(entries(environment.data)):
        raise ScanError("The .env destination already exists; existing values are never overwritten.")
    ignore = read(".gitignore")
    ignore_after = ignore.data
    for relative_name, pattern in ((".env", b"/.env"), (".codeshield/", b"/.codeshield/")):
        if not is_ignored(git, relative_name):
            ignore_after = append_line(ignore_after, pattern)
    if ignore_after != ignore.data:
        edits.append(Edit(ignore, ignore_after))
    example = read(".env.example")
    present = [value for key, value in entries(example.data) if key == name]
    if present and (len(present) != 1 or present[0].strip()):
        raise ScanError("The example environment destination is nonblank or duplicated; resolve it manually.")
    if not present:
        validate_dotenv(example.data)
        edits.append(Edit(example, append_line(example.data, (name + "=").encode())))
    if store_secret:
        validate_dotenv(environment.data)
        value = candidate.value
        if any(ord(c) < 32 or c in "'\\$" for c in value):
            raise ScanError("This credential cannot be stored as a safe single-line dotenv literal.")
        environment.writable()
        edits.append(Edit(environment, append_line(environment.data, (name + "='" + value + "'").encode("utf-8")), True))
    edits.append(Edit(source, after))
    for edit in edits:
        edit.before.writable()
        if len(edit.after) > config.max_file_bytes:
            raise ScanError("Proposed file exceeds the configured size limit.")
        # Existing auxiliary project files must have an exact staged snapshot.
        if edit.before.relative not in (relative, ".env") and edit.before.data is not None:
            rows = git.run("ls-files", "--stage", "-z", "--", edit.before.relative).split(b"\0")
            if not rows[0]:
                raise ScanError("Stage auxiliary configuration intentionally before allowing it to be updated.")
            header, _ = rows[0].split(b"\t", 1)
            mode, oid, stage = header.split()
            if mode not in (b"100644", b"100755") or stage != b"0" or not index_equivalent(edit.before.data, git.run("cat-file", "blob", oid.decode())):
                raise ScanError("Auxiliary configuration has unstaged changes or unsafe tracking state.")
    # Guard every inspected manifest, including paths absent while planning.
    if index != git.run("ls-files", "--stage", "-z") or head != git.run("rev-parse", "--revs-only", "HEAD"):
        raise ScanError("Index or HEAD changed while planning; rerun the staged scan.")
    for snapshot in guards.values():
        snapshot.verify(git.root, config.max_file_bytes)
    return Plan(git, config, finding, runtime, name, tuple(edits), guards, index, head, adds_import=add_import)
