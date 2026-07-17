"""Side-effect-free validation for the honeypot's live render dependencies.

The public ``GET /`` path both evaluates a ten-expression Faker varList and
renders the active Jinja template.  A health probe must verify those artifacts
without assigning a real canary set or touching research state. These helpers
compile expressions, evaluate them only against a disposable copy of the live
Faker providers, and render the template with deterministic sentinel values.
"""

from __future__ import annotations

import ast
import copy
from pathlib import Path
from typing import Callable


CANARY_COUNT = 10
_SENTINEL_VALUES = tuple(f"health-canary-{index}" for index in range(1, 11))
_SAFE_RESULT_ATTRIBUTES = frozenset({
    "capitalize", "lower", "strip", "title", "upper", "year",
})
_SAFE_AST_NODES = (
    ast.Expression,
    ast.Constant,
    ast.Name,
    ast.Load,
    ast.Attribute,
    ast.Call,
    ast.keyword,
    ast.BinOp,
    ast.Add,
    ast.UnaryOp,
    ast.UAdd,
    ast.USub,
)


def load_canary_expressions(
    path: str | Path,
    fake,
    *,
    validate_runtime: bool = False,
) -> tuple[str, ...]:
    """Load and safely validate the exact ten expressions used by ``GET /``.

    ``compile(..., mode="eval")`` catches syntax errors without executing an
    expression.  Direct ``fake.<provider>`` attributes are also resolved so a
    missing Faker provider fails health before a visitor gets a 500. When
    ``validate_runtime`` is requested, expressions are evaluated against a
    deep-copied Faker instance: this catches bad arguments/operators/returned
    attributes while preserving the live generator's PRNG state and never
    assigning or persisting the disposable values as canaries.
    """

    source = Path(path)
    # Match set_vars' runtime contract: only the first ten physical lines are
    # canary slots. Requiring all ten makes a truncated/blank deployment fail
    # closed instead of silently falling through to unrelated function defaults.
    lines = source.read_text(encoding="utf-8").splitlines()[:CANARY_COUNT]
    if len(lines) != CANARY_COUNT:
        raise ValueError(
            f"{source.name} must contain {CANARY_COUNT} canary expressions; "
            f"found {len(lines)}"
        )

    expressions = []
    compiled_expressions = []
    for index, raw_expression in enumerate(lines, 1):
        expression = raw_expression.strip()
        if not expression:
            raise ValueError(f"{source.name} canary expression {index} is blank")
        try:
            tree = ast.parse(expression, filename=str(source), mode="eval")
            compiled = compile(tree, str(source), "eval")
        except (SyntaxError, ValueError) as exc:
            raise ValueError(
                f"{source.name} canary expression {index} is invalid"
            ) from exc

        # Evaluation is intentionally restricted to the project's documented
        # Faker-expression grammar. This prevents health validation itself from
        # running builtins/imports or traversing Python internals.
        for node in ast.walk(tree):
            if not isinstance(node, _SAFE_AST_NODES):
                raise ValueError(
                    f"{source.name} canary expression {index} uses unsupported syntax"
                )
            if isinstance(node, ast.Name) and node.id != "fake":
                raise ValueError(
                    f"{source.name} canary expression {index} references "
                    f"unsupported name {node.id!r}"
                )
            if isinstance(node, ast.Attribute):
                direct_faker = (
                    isinstance(node.value, ast.Name)
                    and node.value.id == "fake"
                )
                if (
                    node.attr.startswith("_")
                    or (not direct_faker and node.attr not in _SAFE_RESULT_ATTRIBUTES)
                ):
                    raise ValueError(
                        f"{source.name} canary expression {index} uses "
                        f"unsupported attribute {node.attr!r}"
                    )
            if isinstance(node, ast.Call) and not isinstance(node.func, ast.Attribute):
                raise ValueError(
                    f"{source.name} canary expression {index} uses unsupported call"
                )
            if isinstance(node, ast.keyword) and node.arg is None:
                raise ValueError(
                    f"{source.name} canary expression {index} uses unsupported kwargs"
                )

        # Resolve every direct Faker attribute without invoking it. This catches
        # misspelled/uninstalled providers while leaving string transforms such
        # as fake.word().capitalize() alone for normal Python evaluation.
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "fake"
            ):
                continue
            try:
                getattr(fake, node.attr)
            except (AttributeError, KeyError) as exc:
                raise ValueError(
                    f"{source.name} canary expression {index} references "
                    f"unknown Faker provider {node.attr!r}"
                ) from exc
        expressions.append(expression)
        compiled_expressions.append(compiled)

    if validate_runtime:
        try:
            probe_fake = copy.deepcopy(fake)
        except Exception as exc:
            raise ValueError("could not isolate Faker for health validation") from exc
        for index, compiled in enumerate(compiled_expressions, 1):
            try:
                # Match gen_vars' Python eval semantics while confining all Faker
                # randomness to the disposable clone. No result leaves this loop.
                str(eval(compiled, {"fake": probe_fake}))
            except Exception as exc:
                raise ValueError(
                    f"{source.name} canary expression {index} fails at runtime"
                ) from exc

    return tuple(expressions)


def validate_template_render(
    render: Callable[..., str],
    template_name: str,
) -> None:
    """Render both visitor-state branches with inert canary sentinel strings.

    Rendering, rather than merely loading/compiling the root template, resolves
    lazy includes/imports and executes Jinja macro/filter calls.  Both values of
    ``seen_before`` are checked because templates may branch on that state.
    The rendered bytes are deliberately discarded.
    """

    variables = {
        f"var{index}": value
        for index, value in enumerate(_SENTINEL_VALUES, 1)
    }
    for seen_before in (False, True):
        render(
            template_name,
            user_agent="AI-Bot-Defender-Healthcheck/1.0",
            seen_before=seen_before,
            **variables,
        )


def validate_runtime_dependencies(
    render: Callable[..., str],
    template_name: str,
    varlist_path: str | Path,
    fake,
    *,
    genmode: bool,
    required_assets: tuple[str | Path, ...] = (),
) -> None:
    """Validate exactly the artifacts reachable under the active server mode."""

    # `python server.py nogen` renders Null values and never calls set_vars, so
    # its varList is intentionally not a live dependency. The template always is.
    if genmode:
        load_canary_expressions(varlist_path, fake, validate_runtime=True)
    for asset in required_assets:
        asset_path = Path(asset)
        if not asset_path.is_file() or not asset_path.read_bytes():
            raise ValueError(f"required runtime asset is missing or empty: {asset_path}")
    validate_template_render(render, template_name)
