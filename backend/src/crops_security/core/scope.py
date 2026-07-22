from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import urlparse


class ScopeValidationError(ValueError):
    """Raised when a target cannot be safely accepted."""


@dataclass(frozen=True)
class AuthorizedTarget:
    url: str
    hostname: str
    comparable_hostname: str


def normalize_target(raw_target: str) -> AuthorizedTarget:
    target = raw_target.strip()
    if not target:
        raise ScopeValidationError("Informe uma URL para iniciar a análise.")
    if "://" not in target:
        target = f"https://{target}"

    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ScopeValidationError("Use uma URL HTTP ou HTTPS válida.")
    if parsed.username or parsed.password:
        raise ScopeValidationError("A URL não pode conter credenciais.")

    hostname = parsed.hostname.lower().rstrip(".")
    comparable = hostname[4:] if hostname.startswith("www.") else hostname
    path = parsed.path or "/"
    try:
        port = parsed.port
    except ValueError as exc:
        raise ScopeValidationError("A URL contém uma porta inválida.") from exc
    display_hostname = f"[{hostname}]" if ":" in hostname else hostname
    netloc = f"{display_hostname}:{port}" if port else display_hostname
    normalized = parsed._replace(netloc=netloc, path=path, fragment="").geturl()
    return AuthorizedTarget(normalized, hostname, comparable)


def same_scope(url: str, target: AuthorizedTarget) -> bool:
    hostname = (urlparse(url).hostname or "").lower().rstrip(".")
    comparable = hostname[4:] if hostname.startswith("www.") else hostname
    return bool(comparable and comparable == target.comparable_hostname)


def is_public_or_hostname(hostname: str) -> bool:
    """Return False only for literal loopback/link-local addresses.

    Hostnames remain allowed because authorized internal assessments are a valid use case.
    """
    try:
        address = ip_address(hostname)
    except ValueError:
        return True
    return not (address.is_loopback or address.is_link_local or address.is_unspecified)
