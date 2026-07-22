import html
import re
import ssl
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import urldefrag, urljoin, urlparse
from urllib.request import Request, urlopen

from crops_security.core.findings import Finding
from crops_security.core.scope import AuthorizedTarget, normalize_target, same_scope

from .detectors import TextResource, scan_resource

TEXT_EXTENSIONS = {
    ".html",
    ".htm",
    ".xhtml",
    ".js",
    ".mjs",
    ".cjs",
    ".jsx",
    ".ts",
    ".tsx",
    ".css",
    ".json",
    ".map",
    ".xml",
    ".txt",
    ".csv",
    ".yaml",
    ".yml",
    ".ini",
    ".conf",
    ".env",
    ".properties",
    ".toml",
    ".md",
    ".graphql",
    ".gql",
    ".svg",
}
TEXT_CONTENT_TYPES = ("text/", "javascript", "json", "xml", "graphql", "x-www-form-urlencoded")
SKIP_SCHEMES = {"mailto", "tel", "javascript", "data", "blob", "about"}


@dataclass(frozen=True)
class ScanOptions:
    max_urls: int = 80
    depth: int = 2
    timeout_seconds: int = 10
    max_resource_bytes: int = 2_000_000
    include_external: bool = False
    verify_tls: bool = True
    custom_words: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScanOutcome:
    pages_scanned: int
    findings: tuple[Finding, ...]
    errors: tuple[str, ...]


class ReferenceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.references: set[str] = set()

    def handle_starttag(self, _: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): value for name, value in attrs if value}
        for attribute in ("href", "src", "action", "poster"):
            if value := values.get(attribute):
                self.references.add(value)


class SensitiveDataScanner:
    def __init__(self, options: ScanOptions) -> None:
        self.options = options

    def run(
        self,
        raw_target: str,
        progress: Callable[[int, str, int], None] | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> ScanOutcome:
        target = normalize_target(raw_target)
        queue: deque[tuple[str, int]] = deque([(target.url, 0)])
        visited: set[str] = set()
        findings: list[Finding] = []
        errors: list[str] = []

        while queue and len(visited) < self.options.max_urls:
            if cancelled and cancelled():
                break
            url, depth = queue.popleft()
            if url in visited or not self._allowed(url, target):
                continue
            visited.add(url)
            if progress:
                ratio = max(5, min(85, int(len(visited) / self.options.max_urls * 80) + 5))
                progress(ratio, f"Analisando recurso {len(visited)}", len(visited))
            try:
                resource = self._fetch(url)
            except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
                errors.append(f"{url}: {exc}")
                continue
            if resource is None:
                continue
            findings.extend(scan_resource(resource, self.options.custom_words))
            if depth < self.options.depth:
                queue.extend((reference, depth + 1) for reference in self._references(resource))

        deduplicated = {
            (item.indicator, item.url, item.line, item.match_text): item for item in findings
        }
        ordered = sorted(
            deduplicated.values(),
            key=lambda item: (
                {"critical": 0, "high": 1, "medium": 2, "low": 3, "informative": 4}[item.severity],
                item.url,
                item.line,
            ),
        )
        return ScanOutcome(len(visited), tuple(ordered), tuple(errors))

    def _allowed(self, url: str, target: AuthorizedTarget) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return False
        return self.options.include_external or same_scope(url, target)

    def _fetch(self, url: str) -> TextResource | None:
        context = (
            ssl.create_default_context()
            if self.options.verify_tls
            else ssl._create_unverified_context()
        )
        request = Request(
            url,
            headers={
                "User-Agent": "CropsSecurity-SensitiveDataFinder/1.0",
                "Accept": (
                    "text/html,application/json,text/plain,text/css,"
                    "application/javascript,*/*;q=0.5"
                ),
            },
        )
        with urlopen(request, timeout=self.options.timeout_seconds, context=context) as response:
            content_type = response.headers.get("Content-Type", "").lower()
            if not any(
                hint in content_type for hint in TEXT_CONTENT_TYPES
            ) and not self._textual_url(url):
                return None
            raw = response.read(self.options.max_resource_bytes + 1)[
                : self.options.max_resource_bytes
            ]
            charset_match = re.search(r"charset=([\w.-]+)", content_type)
            charset = charset_match.group(1) if charset_match else "utf-8"
            return TextResource(url, raw.decode(charset, errors="replace"))

    def _references(self, resource: TextResource) -> set[str]:
        parser = ReferenceParser()
        try:
            parser.feed(resource.text)
        except Exception:
            pass
        references = set(parser.references)
        references.update(
            match.group(1) for match in re.finditer(r"url\(['\"]?([^'\")]+)", resource.text, re.I)
        )
        normalized: set[str] = set()
        for reference in references:
            reference = html.unescape(reference.strip())
            if not reference or urlparse(reference).scheme.lower() in SKIP_SCHEMES:
                continue
            joined, _ = urldefrag(urljoin(resource.url, reference))
            if self._textual_url(joined):
                normalized.add(joined)
        return normalized

    @staticmethod
    def _textual_url(url: str) -> bool:
        path = urlparse(url).path.lower()
        return (
            not path
            or path.endswith("/")
            or any(path.endswith(extension) for extension in TEXT_EXTENSIONS)
        )
