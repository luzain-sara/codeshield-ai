"""Allowlisted syntax checks. Never import the target module or run project commands."""

import ast
import os
import shutil
import subprocess
from pathlib import Path

from tree_sitter import Language, Parser
import tree_sitter_javascript

from codeshield.errors import ScanError


def javascript_tree(data: bytes):
    tree = Parser(Language(tree_sitter_javascript.language())).parse(data)
    if tree.root_node.has_error:
        raise ScanError("JavaScript parsing failed; no safe patch is available.")
    return tree.root_node


def syntax(data: bytes, runtime: str, root: Path, timeout: int):
    try:
        if runtime == "python":
            # Compile without executing or writing pyc files. Exceptions never include source.
            compile(data, "<codeshield-validation>", "exec", dont_inherit=True)
            ast.parse(data)
            return
        javascript_tree(data)
        executable = shutil.which("node")
        if not executable or Path(executable).resolve().is_relative_to(root):
            raise ScanError("A trusted Node.js executable is required for JavaScript validation.")
        env = {name: os.environ[name] for name in ("SystemRoot", "WINDIR", "TEMP", "TMP", "PATH") if name in os.environ}
        result = subprocess.run(
            [executable, "--check", "--input-type=" + ("module" if runtime == "node_module" else "commonjs"), "-"],
            input=data, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd=root, env=env, timeout=timeout, check=False,
        )
        if result.returncode:
            raise ScanError("Node.js syntax validation failed; no files were approved.")
    except (SyntaxError, ValueError, RecursionError, OSError, subprocess.TimeoutExpired):
        raise ScanError("Syntax validation failed or timed out; no source was displayed.") from None
