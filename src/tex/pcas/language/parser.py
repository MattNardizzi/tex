"""
PCAS recursive-descent parser.

Consumes the token stream from ``Lexer`` and produces a typed
``Program``. All AST nodes carry source positions so the stratifier and
evaluator can emit precise error locations.

Grammar
-------
Mirrors the EBNF in ``tex.pcas.language.ast``. See that module for the
canonical specification. The parser intentionally accepts both:

::

    rule :- atom.
    fact.

By treating the colon-dash optional and the body empty.

Error policy
------------
Parse errors are fatal: this is a *policy* language, and silently
accepting a malformed policy could license dangerous actions. Always
fail-closed; the PDP treats parse errors as FORBID via ``PcasMonitor``.

Reference: arxiv 2602.16708 §4.5.1, §4.5.3 (rule annotations); standard
Datalog recursive-descent following Abiteboul-Hull-Vianu ch.15.
"""

from __future__ import annotations

from tex.pcas.language.ast import (
    Atom,
    Constant,
    HelperCall,
    NegatedAtom,
    Program,
    Rule,
    Term,
    Variable,
)
from tex.pcas.language.lexer import Lexer, Token, TokenKind


class ParseError(Exception):
    """Structured parser failure with token position."""

    def __init__(self, message: str, *, token: Token | None = None) -> None:
        if token is not None and token.kind is not TokenKind.EOF:
            super().__init__(
                f"{message} at token {token.kind.value} {token.text!r} "
                f"(line {token.line}, col {token.col})"
            )
        elif token is not None:
            super().__init__(f"{message} at end of input")
        else:
            super().__init__(message)
        self.message = message
        self.token = token


class Parser:
    """
    Recursive-descent parser. Owns a token index over the stream.

    Single-pass; consume tokens via ``_peek`` / ``_consume``.
    """

    __slots__ = ("_tokens", "_i")

    def __init__(self, tokens: tuple[Token, ...]) -> None:
        if not tokens or tokens[-1].kind is not TokenKind.EOF:
            raise ValueError("token stream must end with EOF")
        self._tokens = tokens
        self._i = 0

    # ------------------------------------------------------------- helpers

    def _peek(self, offset: int = 0) -> Token:
        return self._tokens[self._i + offset]

    def _consume(self, *kinds: TokenKind) -> Token:
        tok = self._tokens[self._i]
        if kinds and tok.kind not in kinds:
            raise ParseError(
                f"expected one of {[k.value for k in kinds]}, got {tok.kind.value}",
                token=tok,
            )
        self._i += 1
        return tok

    def _accept(self, *kinds: TokenKind) -> Token | None:
        tok = self._tokens[self._i]
        if tok.kind in kinds:
            self._i += 1
            return tok
        return None

    # ---------------------------------------------------------------- API

    def parse(self, *, source: str | None = None) -> Program:
        rules: list[Rule] = []
        while self._peek().kind is not TokenKind.EOF:
            rules.append(self._parse_rule())
        return Program(rules=tuple(rules), source=source)

    # ---------------------------------------------------------- productions

    def _parse_rule(self) -> Rule:
        # optional annotation
        annotation: str = "rule"
        ann_tok = self._accept(TokenKind.AT_AUTH, TokenKind.AT_DENY)
        if ann_tok is not None:
            annotation = "authorize" if ann_tok.kind is TokenKind.AT_AUTH else "deny"

        head_tok = self._peek()
        head = self._parse_atom()

        body: tuple = ()
        if self._accept(TokenKind.COLON_DASH) is not None:
            body = self._parse_body()
        self._consume(TokenKind.DOT)

        return Rule(
            annotation=annotation,
            head=head,
            body=body,
            line=head_tok.line,
            col=head_tok.col,
        )

    def _parse_body(self) -> tuple:
        items = [self._parse_body_element()]
        while self._accept(TokenKind.COMMA) is not None:
            items.append(self._parse_body_element())
        return tuple(items)

    def _parse_body_element(self):
        if self._peek().kind is TokenKind.NOT:
            not_tok = self._consume(TokenKind.NOT)
            atom = self._parse_atom()
            return NegatedAtom(atom=atom, line=not_tok.line, col=not_tok.col)
        # positive atom or helper call — disambiguated post-parse by
        # stratifier (Atom for now; lifted to HelperCall by stratify())
        return self._parse_atom()

    def _parse_atom(self) -> Atom:
        name_tok = self._consume(TokenKind.IDENT)
        # zero-arg atoms allowed: ``foo`` or ``foo()``
        args: list[Term] = []
        if self._accept(TokenKind.LPAREN) is not None:
            if self._peek().kind is not TokenKind.RPAREN:
                args.append(self._parse_term())
                while self._accept(TokenKind.COMMA) is not None:
                    args.append(self._parse_term())
            self._consume(TokenKind.RPAREN)
        return Atom(
            predicate=name_tok.text,
            args=tuple(args),
            line=name_tok.line,
            col=name_tok.col,
        )

    def _parse_term(self) -> Term:
        tok = self._peek()
        if tok.kind is TokenKind.IDENT:
            # variable if starts upper or '_', else a 0-arg constant atom is
            # not allowed here — bareword identifiers are variables OR they
            # are zero-arg atoms which aren't valid as terms. We accept
            # only variables.
            self._consume(TokenKind.IDENT)
            return Variable(name=tok.text, line=tok.line, col=tok.col)
        if tok.kind is TokenKind.STRING:
            self._consume(TokenKind.STRING)
            return Constant(value=tok.text, line=tok.line, col=tok.col)
        if tok.kind is TokenKind.INTEGER:
            self._consume(TokenKind.INTEGER)
            return Constant(value=int(tok.text), line=tok.line, col=tok.col)
        if tok.kind is TokenKind.BOOL:
            self._consume(TokenKind.BOOL)
            return Constant(value=(tok.text == "true"), line=tok.line, col=tok.col)
        raise ParseError(f"expected term, got {tok.kind.value}", token=tok)


def parse_program(source: str, *, name: str | None = None) -> Program:
    """One-shot convenience: lex + parse a source string."""
    tokens = Lexer(source).tokens()
    return Parser(tokens).parse(source=name)


__all__ = ["ParseError", "Parser", "parse_program"]
