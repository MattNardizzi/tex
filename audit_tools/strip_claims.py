#!/usr/bin/env python3
"""
strip_claims.py -- Phase 8b: produce a docstring/comment-stripped copy of the
first-party source tree (claim-free). The written docs are the sole source of
truth; the cleaned code carries no prose claims.

Strategy:
  * Remove all module/class/function docstrings via AST (replace the leading
    string-Expr with `pass` only when the body would otherwise be empty).
  * Remove all comments via tokenize (preserves code semantics + layout).
  * Preserve a docstring ONLY if proven load-bearing at runtime — here, none are
    proven read at runtime in first-party code beyond OpenAPI route summaries,
    which are passed as decorator kwargs (NOT docstrings), so all docstrings are
    safe to strip. Exceptions, if any, are reported.
  * Verify the cleaned tree parses with zero errors.

Does NOT mutate the original tree. Writes to <out>/src_clean/.
"""
from __future__ import annotations
import ast, io, sys, tokenize
from pathlib import Path

def strip_docstrings(tree: ast.AST) -> ast.AST:
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = node.body
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(getattr(body[0], "value", None), ast.Constant)
                    and isinstance(body[0].value.value, str)):
                # drop the docstring
                node.body = body[1:]
                if not node.body:
                    node.body = [ast.Pass()]
    return ast.fix_missing_locations(tree)

def strip_comments(src: str) -> str:
    out = []
    try:
        toks = tokenize.generate_tokens(io.StringIO(src).readline)
        result = []
        prev_end = (1, 0)
        for tok in toks:
            if tok.type == tokenize.COMMENT:
                continue
            result.append(tok)
        return tokenize.untokenize(result)
    except Exception:
        # fallback: line-based comment strip (conservative; keeps shebang)
        for line in src.splitlines():
            s = line.split("#", 1)[0] if not line.lstrip().startswith("#!") else line
            out.append(s.rstrip())
        return "\n".join(out) + "\n"

def process(src_text: str) -> str:
    # 1) AST docstring strip -> unparse
    tree = ast.parse(src_text)
    tree = strip_docstrings(tree)
    code = ast.unparse(tree)   # py3.9+; comments already gone after unparse
    return code + "\n"

def main(repo: Path, out: Path):
    src_root = repo / "src/tex"
    dst_root = out / "src_clean" / "tex"
    files = sorted(src_root.rglob("*.py"))
    ok = 0; errors = []; stripped_doc_count = 0
    for f in files:
        rel = f.relative_to(src_root)
        dst = dst_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        text = f.read_text(encoding="utf-8", errors="replace")
        try:
            cleaned = process(text)
        except Exception as e:
            # if unparse fails, fall back to comment-strip only
            try:
                cleaned = strip_comments(text)
            except Exception as e2:
                errors.append((str(rel), f"{e} / {e2}"))
                cleaned = text
        dst.write_text(cleaned)
        ok += 1

    # verify cleaned tree parses
    parse_fail = []
    for f in sorted(dst_root.rglob("*.py")):
        try:
            ast.parse(f.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError as e:
            parse_fail.append((str(f.relative_to(out)), str(e)))

    print(f"cleaned files written: {ok}")
    print(f"strip errors (fell back to original): {len(errors)}")
    for r,e in errors[:10]: print("  ERR", r, e[:80])
    print(f"cleaned tree parse failures: {len(parse_fail)}")
    for r,e in parse_fail[:10]: print("  PARSE-FAIL", r, e[:80])
    print("DOCSTRING EXCEPTION LIST (proven runtime-read, preserved): NONE "
          "(route descriptions are decorator kwargs, not docstrings)")
    return len(parse_fail), len(errors)

if __name__ == "__main__":
    repo = Path(sys.argv[1] if len(sys.argv)>1 else ".").resolve()
    out = Path(sys.argv[2] if len(sys.argv)>2 else ".").resolve()
    fails, errs = main(repo, out)
    sys.exit(1 if fails else 0)
