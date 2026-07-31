"""
PCAS policy-language lexer.

Tokenizes the surface syntax described in
``tex.pcas.language.ast``. Hand-rolled finite-state lexer; no third-party
parser combinator dependency.

Token taxonomy
--------------
- ``IDENT``       — identifier (relation, helper, or variable name)
- ``INTEGER``     — decimal integer literal (sign handled by parser)
- ``STRING``      — double-quoted string with ``\\`` escapes
- ``BOOL``        — ``true`` / ``false`` keywords
- ``LPAREN``      ``RPAREN``        — ``(`` ``)``
- ``COMMA``       — ``,``
- ``DOT``         — ``.``
- ``COLON_DASH``  — ``:-``
- ``NOT``         — ``not`` keyword
- ``AT_AUTH``     — ``@authorize`` annotation
- ``AT_DENY``     — ``@deny``      annotation
- ``EOF``

Comments
--------
- Line comment: ``%`` to end of line (Datalog tradition; matches CLP /
  Soufflé / PCAS examples in arxiv 2602.16708 appendix A).
- Block comment: ``/* ... */`` (non-nesting).

Whitespace is insignificant. Line / column tracking is 1-indexed for
human-readable error messages.

This module is exception-rich on purpose: every malformed input must
produce a structured ``LexerError`` with byte offset, line, and column
so policy authors can locate the failure.
"""

from __future__ import annotations

from enum import Enum
from typing import Final

from pydantic import BaseModel, ConfigDict, Field


class TokenKind(str, Enum):
    IDENT = "IDENT"
    INTEGER = "INTEGER"
    STRING = "STRING"
    BOOL = "BOOL"
    LPAREN = "LPAREN"
    RPAREN = "RPAREN"
    COMMA = "COMMA"
    DOT = "DOT"
    COLON_DASH = "COLON_DASH"
    NOT = "NOT"
    AT_AUTH = "AT_AUTH"
    AT_DENY = "AT_DENY"
    EOF = "EOF"


class Token(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: TokenKind
    text: str
    line: int = Field(ge=1)
    col: int = Field(ge=1)
    offset: int = Field(ge=0)


class LexerError(Exception):
    """Structured lexer failure with source position."""

    def __init__(self, message: str, *, line: int, col: int, offset: int) -> None:
        super().__init__(f"{message} (line {line}, col {col})")
        self.message = message
        self.line = line
        self.col = col
        self.offset = offset


_KEYWORDS: Final[dict[str, TokenKind]] = {
    "not": TokenKind.NOT,
    "true": TokenKind.BOOL,
    "false": TokenKind.BOOL,
}


_ANNOTATIONS: Final[dict[str, TokenKind]] = {
    "@authorize": TokenKind.AT_AUTH,
    "@deny": TokenKind.AT_DENY,
}


class Lexer:
    """
    Streaming lexer. Construct with the source text, then iterate
    ``tokens()``. Idempotent — multiple ``tokens()`` calls re-scan from
    the start; the lexer holds no consumed state between calls.
    """

    __slots__ = ("_src",)

    def __init__(self, source: str) -> None:
        if not isinstance(source, str):
            raise TypeError("Lexer source must be str")
        self._src = source

    # ------------------------------------------------------------------ API

    def tokens(self) -> tuple[Token, ...]:
        out: list[Token] = []
        i = 0
        line = 1
        col = 1
        src = self._src
        n = len(src)

        while i < n:
            ch = src[i]

            # whitespace
            if ch == "\n":
                line += 1
                col = 1
                i += 1
                continue
            if ch in " \t\r":
                col += 1
                i += 1
                continue

            # comments
            if ch == "%":
                while i < n and src[i] != "\n":
                    i += 1
                continue
            if ch == "/" and i + 1 < n and src[i + 1] == "*":
                start_line, start_col = line, col
                i += 2
                col += 2
                while i + 1 < n and not (src[i] == "*" and src[i + 1] == "/"):
                    if src[i] == "\n":
                        line += 1
                        col = 1
                    else:
                        col += 1
                    i += 1
                if i + 1 >= n:
                    raise LexerError(
                        "unterminated block comment",
                        line=start_line,
                        col=start_col,
                        offset=i,
                    )
                i += 2
                col += 2
                continue

            # punctuation
            if ch == "(":
                out.append(
                    Token(kind=TokenKind.LPAREN, text="(", line=line, col=col, offset=i)
                )
                i += 1
                col += 1
                continue
            if ch == ")":
                out.append(
                    Token(kind=TokenKind.RPAREN, text=")", line=line, col=col, offset=i)
                )
                i += 1
                col += 1
                continue
            if ch == ",":
                out.append(
                    Token(kind=TokenKind.COMMA, text=",", line=line, col=col, offset=i)
                )
                i += 1
                col += 1
                continue
            if ch == ".":
                out.append(
                    Token(kind=TokenKind.DOT, text=".", line=line, col=col, offset=i)
                )
                i += 1
                col += 1
                continue
            if ch == ":":
                if i + 1 < n and src[i + 1] == "-":
                    out.append(
                        Token(
                            kind=TokenKind.COLON_DASH,
                            text=":-",
                            line=line,
                            col=col,
                            offset=i,
                        )
                    )
                    i += 2
                    col += 2
                    continue
                raise LexerError(
                    "expected ':-' after ':'", line=line, col=col, offset=i
                )

            # annotations
            if ch == "@":
                start = i
                start_col = col
                i += 1
                col += 1
                while i < n and (src[i].isalnum() or src[i] == "_"):
                    i += 1
                    col += 1
                ann = src[start:i]
                kind = _ANNOTATIONS.get(ann)
                if kind is None:
                    raise LexerError(
                        f"unknown annotation {ann!r}",
                        line=line,
                        col=start_col,
                        offset=start,
                    )
                out.append(
                    Token(kind=kind, text=ann, line=line, col=start_col, offset=start)
                )
                continue

            # string literal
            if ch == '"':
                start = i
                start_col = col
                start_line = line
                i += 1
                col += 1
                buf: list[str] = []
                while i < n and src[i] != '"':
                    if src[i] == "\\":
                        if i + 1 >= n:
                            raise LexerError(
                                "unterminated escape in string literal",
                                line=line,
                                col=col,
                                offset=i,
                            )
                        nxt = src[i + 1]
                        esc_map = {
                            '"': '"',
                            "\\": "\\",
                            "n": "\n",
                            "t": "\t",
                            "r": "\r",
                        }
                        if nxt not in esc_map:
                            raise LexerError(
                                f"unknown escape \\{nxt}",
                                line=line,
                                col=col,
                                offset=i,
                            )
                        buf.append(esc_map[nxt])
                        i += 2
                        col += 2
                        continue
                    if src[i] == "\n":
                        raise LexerError(
                            "newline inside string literal",
                            line=line,
                            col=col,
                            offset=i,
                        )
                    buf.append(src[i])
                    i += 1
                    col += 1
                if i >= n:
                    raise LexerError(
                        "unterminated string literal",
                        line=start_line,
                        col=start_col,
                        offset=start,
                    )
                # consume closing quote
                i += 1
                col += 1
                out.append(
                    Token(
                        kind=TokenKind.STRING,
                        text="".join(buf),
                        line=start_line,
                        col=start_col,
                        offset=start,
                    )
                )
                continue

            # integer literal (signed parsing left to parser via leading-minus)
            if ch.isdigit() or (
                ch == "-"
                and i + 1 < n
                and src[i + 1].isdigit()
                and (not out or out[-1].kind in (TokenKind.LPAREN, TokenKind.COMMA))
            ):
                start = i
                start_col = col
                if ch == "-":
                    i += 1
                    col += 1
                while i < n and src[i].isdigit():
                    i += 1
                    col += 1
                out.append(
                    Token(
                        kind=TokenKind.INTEGER,
                        text=src[start:i],
                        line=line,
                        col=start_col,
                        offset=start,
                    )
                )
                continue

            # identifier or keyword
            if ch.isalpha() or ch == "_":
                start = i
                start_col = col
                while i < n and (src[i].isalnum() or src[i] == "_"):
                    i += 1
                    col += 1
                text = src[start:i]
                kind = _KEYWORDS.get(text, TokenKind.IDENT)
                out.append(
                    Token(
                        kind=kind, text=text, line=line, col=start_col, offset=start
                    )
                )
                continue

            raise LexerError(
                f"unexpected character {ch!r}", line=line, col=col, offset=i
            )

        out.append(
            Token(kind=TokenKind.EOF, text="", line=line, col=col, offset=n)
        )
        return tuple(out)


__all__ = ["Lexer", "LexerError", "Token", "TokenKind"]
