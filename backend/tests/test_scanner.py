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


def test_extracts_srcset_css_import_and_extended_text_extensions() -> None:
    scanner = SensitiveDataScanner(ScanOptions())
    resource = TextResource(
        "https://app.example.test/index.html",
        """
        <img srcset="/small.svg 1x, /large.svg 2x">
        <style>@import url('/audit.log'); @import "/schema.sql";</style>
        """,
    )

    assert scanner._references(resource) == {
        "https://app.example.test/small.svg",
        "https://app.example.test/large.svg",
        "https://app.example.test/audit.log",
        "https://app.example.test/schema.sql",
    }


def test_accepts_clean_dynamic_routes_and_rejects_clear_binary_assets() -> None:
    scanner = SensitiveDataScanner(ScanOptions())
    resource = TextResource(
        "https://app.example.test/",
        """
        <a href="#section">same document</a>
        <a href="/part1">clean route</a>
        <a href="/search?q=secret">query route</a>
        <a href="/feed.gtl">unknown textual extension</a>
        <img src="/logo.png">
        <a href="/report.pdf">binary report</a>
        """,
    )

    assert scanner._references(resource) == {
        "https://app.example.test/",
        "https://app.example.test/part1",
        "https://app.example.test/search?q=secret",
        "https://app.example.test/feed.gtl",
    }


def test_uses_final_redirect_url_as_base_for_relative_links(monkeypatch) -> None:
    resources = {
        "https://app.example.test/start": TextResource(
            "https://app.example.test/instance-123/",
            '<a href="profile">Profile</a>',
        ),
        "https://app.example.test/instance-123/profile": TextResource(
            "https://app.example.test/instance-123/profile",
            "Profile",
        ),
    }
    scanner = SensitiveDataScanner(ScanOptions(max_urls=5, depth=1))
    fetched: list[str] = []

    def fetch(url: str) -> TextResource | None:
        fetched.append(url)
        return resources.get(url)

    monkeypatch.setattr(scanner, "_fetch", fetch)
    outcome = scanner.run("https://app.example.test/start")

    assert fetched == [
        "https://app.example.test/start",
        "https://app.example.test/instance-123/profile",
    ]
    assert outcome.pages_scanned == 2


def test_fetch_preserves_the_final_url_after_http_redirect(monkeypatch) -> None:
    class Response:
        headers = {"Content-Type": "text/html; charset=utf-8"}

        def __enter__(self):
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def geturl(self) -> str:
            return "https://app.example.test/instance-123/"

        def read(self, _: int) -> bytes:
            return b'<a href="profile">Profile</a>'

    monkeypatch.setattr(
        "crops_security.tools.web.sensitive_data.scanner.urlopen",
        lambda *_args, **_kwargs: Response(),
    )
    scanner = SensitiveDataScanner(ScanOptions())

    resource = scanner._fetch_once("https://app.example.test/start")

    assert resource is not None
    assert resource.url == "https://app.example.test/instance-123/"
    assert scanner._references(resource) == {
        "https://app.example.test/instance-123/profile"
    }


def test_content_type_is_authoritative_for_binary_responses(monkeypatch) -> None:
    class Response:
        headers = {"Content-Type": "image/png"}

        def __enter__(self):
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def geturl(self) -> str:
            return "https://app.example.test/deceptive.js"

        def read(self, _: int) -> bytes:
            raise AssertionError("binary response must not be read")

    monkeypatch.setattr(
        "crops_security.tools.web.sensitive_data.scanner.urlopen",
        lambda *_args, **_kwargs: Response(),
    )

    assert SensitiveDataScanner(ScanOptions())._fetch_once(
        "https://app.example.test/deceptive.js"
    ) is None


def test_extensionless_route_without_content_type_can_still_be_analyzed(monkeypatch) -> None:
    class Response:
        headers: dict[str, str] = {}

        def __enter__(self):
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def geturl(self) -> str:
            return "https://app.example.test/part1"

        def read(self, _: int) -> bytes:
            return b"Extensionless route"

    monkeypatch.setattr(
        "crops_security.tools.web.sensitive_data.scanner.urlopen",
        lambda *_args, **_kwargs: Response(),
    )

    resource = SensitiveDataScanner(ScanOptions())._fetch_once(
        "https://app.example.test/part1"
    )

    assert resource == TextResource(
        "https://app.example.test/part1", "Extensionless route"
    )


def test_does_not_count_non_textual_response_as_analyzed(monkeypatch) -> None:
    scanner = SensitiveDataScanner(ScanOptions(max_urls=5, depth=1))
    resources = {
        "https://app.example.test/": TextResource(
            "https://app.example.test/",
            '<a href="/download">Download</a>',
        ),
        "https://app.example.test/download": None,
    }
    monkeypatch.setattr(scanner, "_fetch", lambda url: resources.get(url))

    outcome = scanner.run("https://app.example.test/")

    assert outcome.pages_scanned == 1
    assert outcome.errors == (
        "https://app.example.test/download: ignorado (conteúdo não textual)",
    )


def test_reports_clear_fetch_reason(monkeypatch) -> None:
    scanner = SensitiveDataScanner(ScanOptions(max_urls=1))

    def unavailable(_: str) -> TextResource | None:
        from crops_security.tools.web.sensitive_data.scanner import ResourceFetchError

        raise ResourceFetchError("tempo limite excedido")

    monkeypatch.setattr(scanner, "_fetch", unavailable)
    outcome = scanner.run("https://app.example.test")

    assert outcome.errors == ("https://app.example.test/: tempo limite excedido",)
