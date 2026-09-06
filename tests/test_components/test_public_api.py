"""The declared surface is what callers get; nothing in __all__ may go missing unnoticed."""

import as4
import as4.peppol


def test_everything_named_in_all_is_importable():
    for module in (as4, as4.peppol):
        for name in module.__all__:
            assert hasattr(module, name), f"{module.__name__}.{name} is named in __all__ but absent"


def test_all_is_sorted_and_unique():
    for module in (as4, as4.peppol):
        assert module.__all__ == sorted(set(module.__all__)), f"{module.__name__}.__all__ is unsorted or repeats"


def test_the_peppol_profile_is_not_in_the_core_namespace():
    """The core tier stays profile-agnostic, so a second profile does not disturb it."""
    assert not [name for name in as4.__all__ if "eppol" in name]
