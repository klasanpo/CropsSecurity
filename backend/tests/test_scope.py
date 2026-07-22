import pytest

from crops_security.core.scope import ScopeValidationError, normalize_target, same_scope


def test_normalizes_hostname_and_removes_fragment() -> None:
    target = normalize_target("WWW.Example.com/app#section")

    assert target.url == "https://www.example.com/app"
    assert target.hostname == "www.example.com"
    assert same_scope("https://example.com/other", target)
    assert not same_scope("https://api.example.com/other", target)


@pytest.mark.parametrize(
    "value",
    ["", "ftp://example.com", "https://admin:secret@example.com"],
)
def test_rejects_unsupported_targets(value: str) -> None:
    with pytest.raises(ScopeValidationError):
        normalize_target(value)
