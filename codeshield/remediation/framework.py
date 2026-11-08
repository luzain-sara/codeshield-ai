"""Conservative runtime identification. No project scripts or package code execute."""

import json
import re
import shlex
from pathlib import PurePosixPath

from codeshield.errors import ScanError

CLIENT_PARTS = {"public", "static", "client", "frontend", "www", "assets", "dist"}
GENERATED_PARTS = {"generated", "__generated__", ".generated", ".next", ".nuxt", ".output"}
CLIENT_PACKAGES = {"vite", "next", "react", "react-dom", "react-native", "vue", "svelte", "webpack", "parcel",
                   "nuxt", "astro", "@angular/core", "rollup", "esbuild", "browserify", "electron", "preact", "lit", "gatsby"}
SERVER_PACKAGES = {"express", "fastify", "koa", "@hapi/hapi", "@nestjs/core"}
CLIENT_CONFIGS = tuple(name + extension for name in ("vite.config", "next.config", "nuxt.config", "astro.config")
                       for extension in (".js", ".ts", ".mjs", ".cjs"))


def identify(relative: str, source: bytes, read):
    parts = PurePosixPath(relative).parts
    if any(part.lower() in CLIENT_PARTS | GENERATED_PARTS for part in parts[:-1]):
        raise ScanError("Client-facing or generated paths require manual remediation.")
    if re.search(rb"(?im)^\s*(?:#|//|/\*|\*)[^\r\n]*(?:@generated|do not edit|auto-?generated|automatically generated|code generated)", source[:4096]):
        raise ScanError("Generated source files require changes to their generator, not an automatic patch.")
    if any(marker in source for marker in (b"NEXT_PUBLIC_", b"VITE_", b"REACT_APP_", b"use client", b"window.", b"document.", b"pyodide", b"pyscript", b"brython")):
        raise ScanError("Client-exposed credentials require manual remediation and rotation.")
    server = False
    module = relative.endswith(".mjs")
    directories = [PurePosixPath("."), *reversed(PurePosixPath(relative).parent.parents), PurePosixPath(relative).parent]
    for directory in dict.fromkeys(directories):
        for config in CLIENT_CONFIGS:
            if read((directory / config).as_posix()).data is not None:
                raise ScanError("Browser framework configuration prevents automatic remediation.")
        metadata = read((directory / "package.json").as_posix()).data
        if metadata is None:
            continue
        try:
            package = json.loads(metadata)
            if (not isinstance(package, dict) or not isinstance(package.get("scripts", {}), dict)
                    or any(not isinstance(package.get(field, {}), dict) for field in
                           ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "engines"))):
                raise ScanError("Package metadata is invalid; runtime cannot be proven safe.")
            deps = {name.lower() for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
                    for name in package.get(field, {})}
            scripts = json.dumps(package.get("scripts", {})).lower()
            exports = json.dumps(package.get("exports", {})).lower()
            if (deps & CLIENT_PACKAGES or any(name.startswith(("@vitejs/", "@next/", "@sveltejs/")) for name in deps)
                    or any(word in scripts for word in ("vite", "next ", "webpack", "parcel", "rollup", "esbuild", "browserify"))
                    or package.get("browser") or '"browser"' in exports):
                raise ScanError("Frontend package configuration prevents automatic remediation.")
            start = package.get("scripts", {}).get("start", "")
            tokens = shlex.split(start) if isinstance(start, str) else []
            node_start = (len(tokens) == 2 and tokens[0].lower() in ("node", "node.exe")
                          and re.fullmatch(r"[A-Za-z0-9_./-]+\.(?:js|cjs|mjs)", tokens[1]) is not None)
            server = server or bool(deps & SERVER_PACKAGES) or node_start
            module = package.get("type") == "module"
        except (ValueError, TypeError, AttributeError, RecursionError):
            raise ScanError("Package metadata is invalid; runtime cannot be proven safe.") from None
    suffix = PurePosixPath(relative).suffix.lower()
    if suffix == ".py":
        return "python"
    if suffix not in (".js", ".cjs", ".mjs") or not server:
        raise ScanError("Unsupported or ambiguous runtime; only Python and identified server-side JavaScript are eligible.")
    return "node_module" if suffix == ".mjs" or (module and suffix != ".cjs") else "node_commonjs"
