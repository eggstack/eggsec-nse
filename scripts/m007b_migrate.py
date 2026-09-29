#!/usr/bin/env python3
"""M007B mechanical migration for stereotyped blocking-TCP libraries.

Rewrites, per file:
- imports (TcpStream/Read/Write -> broker imports)
- register_X_library(lua) -> register_X_library_with_services(lua, ctx, services)
- wraps I/O closures with ctx/services clones (op = "lib.entry")
- parse+connect blocks -> broker_tcp_connect
- write_all(...).ok()/warn/map_err -> broker_send_all equivalents
- read(&mut buf).unwrap_or(0) buffer patterns -> broker_tcp_receive
- set_read/write_timeout -> handle.set_timeouts
- executor_core.rs call-site line

Usage: python3 scripts/m007b_migrate.py src/libraries/xxx.rs
Exits non-zero if no connect block matched (needs manual migration).
Prints a report of replacements made.
"""
import re
import sys
import pathlib

BROKER_IMPORTS = """use crate::brokered_stream::{broker_read_into, broker_write_all};
use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, NseHostServices};"""


def _append_broker_args(text, fname, op):
    """Turn `fname(&ctx, handle.as_mut(), ARGS)` into `fname(&ctx, handle.as_mut(), ARGS, "op")`.

    Scans each call start to its matching close paren (string-aware) and
    inserts `, "op"` before it.
    """
    out = []
    i = 0
    tag = fname + "(&ctx, handle.as_mut(), "
    while True:
        j = text.find(tag, i)
        if j == -1:
            out.append(text[i:])
            break
        out.append(text[i:j])
        k = j + len(tag)
        depth = 1
        instr = None
        n = len(text)
        while k < n:
            c = text[k]
            if instr:
                if c == "\\":
                    k += 1
                elif c == instr:
                    instr = None
            elif c in "\"'":
                instr = c
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        out.append(text[j:k] + f', "{op}")')
        i = k + 1
    return "".join(out)


def find_matching_close(text, open_idx):
    """Find index just AFTER the matching close for the brace/paren opened region.

    open_idx points at `lua.create_function(`. We scan from the first `(` with
    string/char/comment awareness, tracking (){}[] depth; the span ends when
    the opening paren closes.
    """
    paren = text.index("(", open_idx)
    i = paren
    depth = 0
    instr = None  # quote char or None
    in_line_comment = False
    in_block_comment = 0
    n = len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line_comment:
            if c == "\n":
                in_line_comment = False
        elif in_block_comment:
            if c == "*" and nxt == "/":
                in_block_comment -= 1
                i += 1
            elif c == "/" and nxt == "*":
                in_block_comment += 1
                i += 1
        elif instr:
            if c == "\\":
                i += 1  # skip escaped char
            elif c == instr:
                instr = None
            # raw strings r#"..."#: crude handling — treat # as opener hint below
        else:
            if c == "/" and nxt == "/":
                in_line_comment = True
                i += 1
            elif c == "/" and nxt == "*":
                in_block_comment += 1
                i += 1
            elif c in "\"'":
                instr = c
            elif c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
                if depth == 0:
                    return i + 1
        i += 1
    raise ValueError("unbalanced delimiters")


def main():
    path = pathlib.Path(sys.argv[1])
    lib = path.stem  # e.g. versant
    # lua global name: usually == lib, but verify from globals.set
    t = path.read_text()
    orig = t
    report = []

    m = re.search(r'globals\.set\("(\w+)",', t)
    lua_global = m.group(1) if m else lib
    pending_rewire = None  # set when a 2-arg rename lands; acted on only if
    converted = 0  # entry bodies fully converted (else nothing is written)

    # 1. imports
    t2 = re.sub(
        r"use std::io::\{Read, Write\};\nuse std::net::TcpStream;\n",
        BROKER_IMPORTS + "\n",
        t,
    )
    if t2 == t:
        t2 = re.sub(
            r"use std::net::TcpStream;\n", BROKER_IMPORTS + "\n", t2
        )
    # lone Read/Write import without TcpStream on next line
    t2 = re.sub(r"use std::io::\{Read, Write\};\n", "", t2)
    if t2 != t:
        report.append("imports swapped")
    t = t2
    # drop subsequent duplicates of the capability-context import
    # (2-arg files already import it; BROKER_IMPORTS repeats it).
    # Operate on lines to avoid spanning matches.
    lines = t.split("\n")
    seen_cap = False
    kept = []
    for ln in lines:
        if ln == "use crate::capabilities::NseCapabilityContext;":
            if seen_cap:
                continue
            seen_cap = True
        kept.append(ln)
    t = "\n".join(kept)

    # 2. register fn rename (+ doc comment); skip if already migrated.
    # Handles both the plain M005E form `register_x_library(lua: &Lua)` and
    # the transitional 2-arg form `register_x_library(lua, capability_ctx)`.
    if f"register_{lib}_library_with_services" not in t:
        t2 = re.sub(
            rf"pub fn register_{lib}_library\(lua: &Lua\)(?!,)",
            f"/// Provider-backed {lib} registration.\n///\n"
            f"/// `services` backs every TCP connect/send/receive path.\n"
            f"pub fn register_{lib}_library_with_services(\n"
            f"    lua: &Lua,\n"
            f"    capability_ctx: &NseCapabilityContext,\n"
            f"    services: &NseHostServices,\n"
            f")",
            t,
            count=1,
        )
        if t2 == t:
            t2 = re.sub(
                rf"pub fn register_{lib}_library\(lua: &Lua, capability_ctx: &NseCapabilityContext\)",
                f"/// Provider-backed {lib} registration.\n///\n"
                f"/// `services` backs every TCP connect/send/receive path.\n"
                f"pub fn register_{lib}_library_with_services(\n"
                f"    lua: &Lua,\n"
                f"    capability_ctx: &NseCapabilityContext,\n"
                f"    services: &NseHostServices,\n"
                f")",
                t,
                count=1,
            )
            if t2 != t:
                report.append("register 2-arg fn renamed")
                # NOTE: the executor_core call-site rewire happens at the end,
                # only if at least one entry body converts (else a SKIP would
                # leave a phantom call site). Stash the intent here.
                pending_rewire = lib
        if t2 == t:
            print(f"SKIP {lib}: register fn signature not matched")
            return 1
        report.append("register fn renamed")
        t = t2

    # 3/4. find create_function spans; wrap I/O ones; rewrite bodies
    # collect spans first (offsets shift as we edit -> work back to front)
    spans = []  # (start_of_`lua.create_function`, end_after_close)
    for m in re.finditer(r"lua\.create_function\(", t):
        end = find_matching_close(t, m.start())
        spans.append((m.start(), end))
    # entry names: search backwards from span start for `.set("ENTRY",`
    jobs = []
    for (s, e) in spans:
        body = t[s:e]
        if "TcpStream::connect" not in body and "stream." not in body:
            continue
        if "capability_ctx.clone()" in body:
            continue  # already migrated (idempotent re-run)
        back = t[max(0, s - 400):s]
        em = None
        for em in re.finditer(r'\.set\(\s*"(\w+)",', back):
            pass
        entry = em.group(1) if em else "unknown"
        jobs.append((s, e, entry, body))

    if not jobs:
        print(f"SKIP {lib}: no I/O closures matched")
        return 1

    for (s, e, entry, body) in reversed(jobs):
        op = f"{lua_global}.{entry}"
        new_body = body
        # 4a. wrap opening: create_function(|lua,  OR create_function(\n |lua,
        # OR create_function(move |lua, (already capturing, e.g. `cap`)
        new_body2, n1 = re.subn(
            r"lua\.create_function\(move \|lua,",
            "lua.create_function({\n            let ctx = capability_ctx.clone();\n"
            "            let services = services.clone();\n"
            "            move |lua,",
            new_body,
            count=1,
        )
        if n1 == 0:
            new_body2, n1 = re.subn(
                r"lua\.create_function\(\|lua,",
                "lua.create_function({\n            let ctx = capability_ctx.clone();\n"
                "            let services = services.clone();\n"
                "            move |lua,",
                new_body,
                count=1,
            )
        if n1 == 0:
            new_body2, n1 = re.subn(
                r"lua\.create_function\(\s*\|lua,",
                "lua.create_function({\n            let ctx = capability_ctx.clone();\n"
                "            let services = services.clone();\n"
                "            move |lua,",
                new_body,
                count=1,
            )
        if n1 == 0:
            print(f"WARN {lib}.{entry}: closure opening not matched, skipped")
            continue
        new_body = new_body2
        # 4b. close: this span ends at the `)` closing create_function, i.e.
        # new_body ends with `}` (closure body) + optional stale trailing `,`
        # + `)`. Drop the stale comma and close the wrapper block:
        # `})` -> `}})`, `},\n)` -> `}\n})`.
        mclose = re.search(r"\},?\s*\)\s*$", new_body)
        if not mclose:
            print(f"WARN {lib}.{entry}: closure close not matched, skipped")
            continue
        new_body = new_body[: mclose.start()] + "}\n})" + new_body[mclose.end():]
        # 4c. parse+connect block -> broker connect (capture port expr + timeout)
        pat_connect = re.compile(
            r'[ \t]*let addr = format!\("\{\}:\{\}", host, (?P<port>[^;]+)\);\n'
            r"(?P<parse>[ \t]*let socket_addr = match addr\.parse::<std::net::SocketAddr>\(\) \{\n"
            r"(?:.*\n)*?"
            r"[ \t]*\};\n)"
            r"[ \t]*let mut stream =\s*match TcpStream::connect_timeout\(\s*&socket_addr,\s*Duration::from_secs\((?P<tout>\d+)\),?\s*\)[^\n]*\n"
            r"(?:[ \t]*\{\n)?"
            r"[ \t]*Ok\(s\) => s,\n"
            r"[ \t]*Err\(e\) => \{\n"
            r"[ \t]*result\.set\(\"status\", \"error\"\)\?;\n"
            r"[ \t]*result\.set\(\"error\", e\.to_string\(\)\)\?;\n"
            r"[ \t]*return Ok\(result\);\n"
            r"[ \t]*\}\n"
            r"[ \t]*\};\n",
        )

        def repl_connect(m):
            return (
                f"            // The broker resolves `host` (authority-preserving);\n"
                f"            // unresolvable or refused hosts keep the error-table shape.\n"
                f"            let (mut handle, _endpoint) = match broker_tcp_connect(\n"
                f"                &ctx,\n"
                f"                &services,\n"
                f"                &host,\n"
                f"                {m.group('port')},\n"
                f"                Duration::from_secs({m.group('tout')}),\n"
                f'                "{op}",\n'
                f"            ) {{\n"
                f"                Ok(pair) => pair,\n"
                f"                Err(e) => {{\n"
                f'                    result.set("status", "error")?;\n'
                f'                    result.set("error", e)?;\n'
                f"                    return Ok(result);\n"
                f"                }}\n"
                f"            }};\n"
            )

        new_body, nconn = pat_connect.subn(repl_connect, new_body)
        report.append(f"{entry}: {nconn} connect block(s)")
        if nconn == 0:
            print(f"WARN {lib}.{entry}: connect block not matched")
            continue
        # 4d. drop-in I/O swaps (io::Result helpers preserve every call shape:
        # .ok(), .unwrap_or_else, .map_err(..)?, if-let, match, `?`).
        # Method calls may span lines (`stream\n.write_all(..)`), hence \s*.
        new_body, nw = re.subn(
            r"stream\s*\.\s*write_all\(",
            f'broker_write_all(&ctx, handle.as_mut(), ',
            new_body,
        )
        # close the extra open paren: broker_write_all(ctx, handle, EXPR, "op")
        # EXPR was the sole write_all arg; append the missing tail args.
        # Handle by rewriting `broker_write_all(&ctx, handle.as_mut(), ARGS)` endings:
        # find each broker_write_all( start, scan to its matching close, append.
        new_body = _append_broker_args(new_body, "broker_write_all", op)
        new_body, nr = re.subn(
            r"stream\s*\.\s*read\(",
            f'broker_read_into(&ctx, handle.as_mut(), ',
            new_body,
        )
        new_body = _append_broker_args(new_body, "broker_read_into", op)
        report.append(f"{entry}: writes={nw} reads={nr}")
        t = t[:s] + new_body + t[e:]
        converted += 1

    # 5. timeouts: set_read/write_timeout(X) -> handle.set_timeouts(X).
    # Provider takes a bare Duration; unwrap literal Some(..) textually.
    # Calls may span lines (`stream\n.set_read_timeout(..)`), hence \s*.
    t = re.sub(
        r"stream\s*\.\s*set_(?:read|write)_timeout\(Some\((?P<e>.*)\)\)",
        r"handle.set_timeouts(\g<e>)",
        t,
    )
    t = re.sub(
        r"stream\s*\.\s*set_(?:read|write)_timeout\((?P<e>[^,();]+)\)",
        r"handle.set_timeouts(\g<e>)",
        t,
    )

    if converted == 0:
        print(f"SKIP {lib}: no entry bodies converted, nothing written")
        return 1

    if pending_rewire is not None:
        core = pathlib.Path("src/executor_core.rs")
        ct = core.read_text()
        old_call = f"register_{pending_rewire}_library(&ctx.lua, &ctx.capability_context)"
        new_call = (
            f"register_{pending_rewire}_library_with_services(\n"
            f"                    &ctx.lua,\n"
            f"                    &ctx.capability_context,\n"
            f"                    &ctx.host_services,\n"
            f"                )"
        )
        assert old_call in ct, f"call site for {pending_rewire} not found"
        core.write_text(ct.replace(old_call, new_call, 1))
        report.append("executor_core call site rewired")

    path.write_text(t)
    print(f"OK {lib}: " + "; ".join(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
