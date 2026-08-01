from __future__ import annotations

from rich.console import Console

from cryptolab.mathematics.algebra import (
    GroupOperation,
    describe_zn,
    element_order,
    generated_subgroup,
    group_generators,
    primitive_roots,
)
from cryptolab.rendering.algebra import (
    ElementOrderView,
    GeneratedSubgroupView,
    GeneratorCollectionView,
    ZnStructureView,
)


def render_text(view: object, *, explain: bool = True) -> str:
    console = Console(record=True, force_terminal=False, no_color=True)
    view.render_human(console, explain=explain)  # type: ignore[attr-defined]
    return console.export_text(clear=False)


def test_zn_structure_view_all_formats() -> None:
    view = ZnStructureView(describe_zn(15))
    assert "Integral domain" in render_text(view)
    assert view.render_json(explain=True)["trace"]
    assert "mathbb" in view.render_latex(explain=True)


def test_element_order_view_all_formats() -> None:
    view = ElementOrderView(element_order(5, 17, GroupOperation.ADDITIVE))
    assert "Order of 5" in render_text(view)
    assert view.render_json(explain=True)["result"]["order"] == 17
    assert "operatorname" in view.render_latex(explain=False)


def test_subgroup_view_all_formats() -> None:
    view = GeneratedSubgroupView(generated_subgroup(6, 15, GroupOperation.ADDITIVE))
    assert "Subgroup order: 5" in render_text(view)
    assert view.render_json(explain=False)["result"]["elements"] == [0, 6, 12, 3, 9]
    assert "langle" in view.render_latex(explain=False)


def test_generator_views_for_cyclic_and_noncyclic_groups() -> None:
    roots = GeneratorCollectionView(
        primitive_roots(17),
        command="algebra.primitive-roots",
    )
    assert "Generators" in render_text(roots)
    assert roots.render_json(explain=True)["result"]["cyclic"] is True
    assert "Gen" in roots.render_latex(explain=False)

    noncyclic = GeneratorCollectionView(group_generators(8, GroupOperation.MULTIPLICATIVE))
    assert "not cyclic" in render_text(noncyclic)
