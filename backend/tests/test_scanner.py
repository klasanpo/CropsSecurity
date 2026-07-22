from crops_security.tools.web.sensitive_data.detectors import TextResource
from crops_security.tools.web.sensitive_data.scanner import ScanOptions, SensitiveDataScanner


def test_crawler_respects_scope_depth_and_url_limit(monkeypatch) -> None:
    resources = {
        "https://app.example.test/": TextResource(
            "https://app.example.test/",
            '<script src="/app.js"></script><a href="https://outside.test/leak.js">outside</a>',
        ),
        "https://app.example.test/app.js": TextResource(
            "https://app.example.test/app.js",
            'const client_secret = "Production-Secret-4839";',
        ),
    }
    scanner = SensitiveDataScanner(ScanOptions(max_urls=2, depth=2))
    fetched: list[str] = []

    def fetch(url: str) -> TextResource | None:
        fetched.append(url)
        return resources.get(url)

    monkeypatch.setattr(scanner, "_fetch", fetch)
    outcome = scanner.run("https://app.example.test")

    assert outcome.pages_scanned == 2
    assert fetched == ["https://app.example.test/", "https://app.example.test/app.js"]
    assert [finding.indicator for finding in outcome.findings] == ["Assignment: client_secret"]


def test_crawler_stops_cooperatively_before_fetch(monkeypatch) -> None:
    scanner = SensitiveDataScanner(ScanOptions())
    monkeypatch.setattr(
        scanner,
        "_fetch",
        lambda _: (_ for _ in ()).throw(AssertionError("fetch should not run")),
    )

    outcome = scanner.run("https://app.example.test", cancelled=lambda: True)

    assert outcome.pages_scanned == 0
    assert outcome.findings == ()
