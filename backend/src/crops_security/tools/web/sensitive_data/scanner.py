import html
import re
import socket
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

TEXT_CONTENT_TYPES = (
    "text/",
    "javascript",
    "json",
    "xml",
    "graphql",
    "rss",
    "atom",
    "x-www-form-urlencoded",
)
BINARY_EXTENSIONS = {
    ".7z",
    ".apk",
    ".avi",
    ".avif",
    ".bin",
    ".bmp",
    ".bz2",
    ".class",
    ".deb",
    ".dmg",
    ".doc",
    ".docx",
    ".eot",
    ".exe",
    ".flac",
    ".gif",
    ".gz",
    ".ico",
    ".iso",
    ".jar",
    ".jpeg",
    ".jpg",
    ".m4a",
    ".mkv",
    ".mov",
    ".mp3",
    ".mp4",
    ".mpeg",
    ".mpg",
    ".otf",
    ".pdf",
    ".pkg",
    ".png",
    ".ppt",
    ".pptx",
    ".rar",
    ".rpm",
    ".tar",
    ".tgz",
    ".ttf",
    ".wav",
    ".wasm",
    ".webm",
    ".webp",
    ".woff",
    ".woff2",
    ".xls",
    ".xlsx",
    ".xz",
    ".zip",
}
SKIP_SCHEMES = {"mailto", "tel", "javascript", "data", "blob", "about", "chrome"}


@dataclass(frozen=True)
class ScanOptions:
    max_urls: int = 200
    depth: int = 2
    timeout_seconds: int = 10
    max_resource_bytes: int = 2_000_000
    include_external: bool = False
    verify_tls: bool = True
    custom_words: tuple[str, ...] = ()
    context_chars: int = 1500


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
        if srcset := values.get("srcset"):
            for item in srcset.split(","):
                if candidate := item.strip().split(" ", 1)[0]:
                    self.references.add(candidate)


class ResourceFetchError(RuntimeError):
    """A fetch failure formatted for the operator without a traceback."""


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
        attempted: set[str] = set()
        analyzed: set[str] = set()
        findings: list[Finding] = []
        errors: list[str] = []

        while queue and len(attempted) < self.options.max_urls:
            if cancelled and cancelled():
                break
            url, depth = queue.popleft()
            if url in attempted or url in analyzed or not self._allowed(url, target):
                continue
            attempted.add(url)
            if progress:
                ratio = max(5, min(85, int(len(attempted) / self.options.max_urls * 80) + 5))
                progress(ratio, f"Obtendo recurso {len(attempted)}", len(analyzed))
            try:
                resource = self._fetch(url)
            except ResourceFetchError as exc:
                errors.append(f"{url}: {exc}")
                continue
            if resource is None:
                errors.append(f"{url}: ignorado (conteúdo não textual)")
                continue
            if not self._allowed(resource.url, target):
                errors.append(
                    f"{url}: ignorado (redirecionamento fora do escopo para {resource.url})"
                )
                continue
            if resource.url in analyzed:
                continue
            analyzed.add(resource.url)
            if progress:
                progress(ratio, f"Analisando recurso {len(analyzed)}", len(analyzed))
            findings.extend(
                scan_resource(
                    resource,
                    self.options.custom_words,
                    context_chars=self.options.context_chars,
                )
            )
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
        return ScanOutcome(len(analyzed), tuple(ordered), tuple(errors))

    def _allowed(self, url: str, target: AuthorizedTarget) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return False
        return self.options.include_external or same_scope(url, target)

    def _fetch(self, url: str) -> TextResource | None:
        try:
            return self._fetch_once(url)
        except HTTPError as exc:
            raise ResourceFetchError(f"HTTP {exc.code} ({exc.reason})") from exc
        except URLError as exc:
            if self._is_dns_error(exc):
                fallback = self._www_fallback(url)
                if fallback:
                    try:
                        return self._fetch_once(fallback)
                    except HTTPError as fallback_exc:
                        raise ResourceFetchError(
                            f"DNS falhou; fallback www retornou HTTP {fallback_exc.code}"
                        ) from fallback_exc
                    except (URLError, TimeoutError, OSError, ValueError) as fallback_exc:
                        raise ResourceFetchError(
                            f"DNS falhou; fallback www indisponível ({fallback_exc})"
                        ) from fallback_exc
            if self._is_tls_error(exc):
                raise ResourceFetchError(
                    "falha TLS; o certificado não foi ignorado automaticamente"
                ) from exc
            raise ResourceFetchError(f"falha de conexão ({exc.reason})") from exc
        except TimeoutError as exc:
            raise ResourceFetchError("tempo limite excedido") from exc
        except (OSError, ValueError) as exc:
            raise ResourceFetchError(f"recurso indisponível ({exc})") from exc

    def _fetch_once(self, url: str) -> TextResource | None:
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
            final_url, _ = urldefrag(response.geturl())
            content_type = response.headers.get("Content-Type", "").lower()
            textual_type = any(hint in content_type for hint in TEXT_CONTENT_TYPES)
            generic_type = not content_type or "application/octet-stream" in content_type
            if not textual_type and not (generic_type and self._crawlable_url(final_url)):
                return None
            raw = response.read(self.options.max_resource_bytes + 1)[
                : self.options.max_resource_bytes
            ]
            charset_match = re.search(r"charset=([\w.-]+)", content_type)
            charset = charset_match.group(1) if charset_match else "utf-8"
            return TextResource(final_url, raw.decode(charset, errors="replace"))

    def _references(self, resource: TextResource) -> set[str]:
        parser = ReferenceParser()
        try:
            parser.feed(resource.text)
        except Exception:
            pass
        references = set(parser.references)
        references.update(
            match.group(1)
            for match in re.finditer(
                r"@import\s+(?:url\()?['\"]?([^'\")\s;]+)", resource.text, re.I
            )
        )
        references.update(
            match.group(1)
            for match in re.finditer(r"url\(['\"]?([^'\")]+)['\"]?\)", resource.text, re.I)
        )
        normalized: set[str] = set()
        for reference in references:
            reference = html.unescape(reference.strip())
            if not reference or urlparse(reference).scheme.lower() in SKIP_SCHEMES:
                continue
            joined, _ = urldefrag(urljoin(resource.url, reference))
            if self._crawlable_url(joined):
                normalized.add(joined)
        return normalized

    @staticmethod
    def _is_dns_error(exc: BaseException) -> bool:
        reason = getattr(exc, "reason", exc)
        message = str(reason).lower()
        return isinstance(reason, socket.gaierror) or any(
            marker in message
            for marker in (
                "name or service not known",
                "nodename nor servname",
                "temporary failure",
            )
        )

    @staticmethod
    def _is_tls_error(exc: BaseException) -> bool:
        reason = getattr(exc, "reason", exc)
        message = str(reason).lower()
        return isinstance(reason, ssl.SSLError) or any(
            marker in message for marker in ("certificate", "ssl", "tls")
        )

    @staticmethod
    def _www_fallback(url: str) -> str | None:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        if not hostname or hostname.startswith("www."):
            return None
        display_hostname = f"[www.{hostname}]" if ":" in hostname else f"www.{hostname}"
        netloc = f"{display_hostname}:{parsed.port}" if parsed.port else display_hostname
        return parsed._replace(netloc=netloc).geturl()

    @staticmethod
    def _crawlable_url(url: str) -> bool:
        """Allow clean and unknown routes, rejecting only clearly binary paths.

        The response Content-Type remains authoritative after the request.
        """
        path = urlparse(url).path.lower().rstrip("/")
        filename = path.rsplit("/", 1)[-1]
        if "." not in filename:
            return True
        return not any(filename.endswith(extension) for extension in BINARY_EXTENSIONS)
