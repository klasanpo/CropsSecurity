import bisect
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from crops_security.core.findings import Finding

KNOWN_SECRET_PATTERNS = (
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "critical"),
    ("GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z_]{36,255}\b"), "critical"),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,80}\b"), "critical"),
    (
        "JWT",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
        "critical",
    ),
    ("Bearer token", re.compile(r"\bBearer\s+[A-Za-z0-9._\-+/=]{20,}\b"), "critical"),
    ("Basic authentication", re.compile(r"\bBasic\s+[A-Za-z0-9+/=]{20,}\b"), "high"),
)

SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?ix)\b(?P<key>password|passwd|pwd|senha|secret|segredo|token|access[_-]?token|"
    r"refresh[_-]?token|id[_-]?token|jwt[_-]?secret|api[_-]?key|apikey|client[_-]?secret|"
    r"app[_-]?secret|private[_-]?key|signing[_-]?key|encrypt(?:ion)?[_-]?key|"
    r"decrypt(?:ion)?[_-]?key|db[_-]?(?:pass|password)|database[_-]?password|"
    r"smtp[_-]?(?:pass|password)|aws[_-]?secret[_-]?access[_-]?key|subscription[_-]?key)"
    r"\b\s*(?:=|:)\s*(?P<quote>['\"]?)(?P<value>[^'\"\s,;<>&}{\]]{4,})(?P=quote)"
)
DATABASE_CREDENTIAL_RE = re.compile(
    r"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|amqp)://"
    r"[^\s:/@]{1,128}:[^\s/@]{1,256}@[^\s'\"<>]+"
)
PRIVATE_KEY_BLOCK_RE = re.compile(
    r"(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----).*?"
    r"(-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|$)",
    re.DOTALL,
)
SENSITIVE_FILE_RE = re.compile(
    r"(?i)(?<![\w.-])(?:\.env(?:\.(?:production|prod|staging|local))?|wp-config\.php|"
    r"application\.(?:properties|ya?ml)|appsettings\.json|database\.ya?ml|"
    r"service-account\.json|credentials\.json|id_rsa|authorized_keys)(?![\w.-])"
)
PRIVATE_PATH_RE = re.compile(
    r"(?i)(?<![\w.])(?:"
    r"/(?:var/www|usr/share/nginx|usr/local/apache2|etc/(?:nginx|apache2|httpd|passwd|shadow)|"
    r"var/log/(?:nginx|apache2|httpd)|opt/(?:tomcat|[\w.-]+)|srv/www|root|usr/src/app|"
    r"run/secrets|var/run/(?:secrets/kubernetes\.io|docker\.sock)|etc/kubernetes)"
    r"(?:/[\w.@+ -]+)*|"
    r"[A-Z]:\\(?:inetpub\\wwwroot|Windows\\System32|Program Files|xampp\\htdocs|"
    r"wamp64\\www|Apache24\\htdocs)(?:\\[\w.@+ -]+)*)"
)
INTERNAL_HOST_RE = re.compile(
    r"(?i)\b(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
)
EMAIL_RE = re.compile(r"(?i)(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}(?![\w.-])")
CPF_RE = re.compile(r"(?<!\d)(?:\d{3}\.\d{3}\.\d{3}-\d{2}|\d{11})(?!\d)")
CNPJ_RE = re.compile(r"(?<!\d)(?:\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}|\d{14})(?!\d)")
CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
RG_CONTEXT_RE = re.compile(
    r"(?i)\b(?:rg|registro\s+geral|identidade)\b\s*(?:=|:|-)?\s*['\"]?"
    r"(?P<value>\d{1,2}\.?\d{3}\.?\d{3}-?[\dXx])['\"]?"
)
NEGATIVE_CONTEXT_RE = re.compile(
    r"(?i)(?:<input\b|type\s*=\s*['\"]password|<label\b|placeholder\s*=|autocomplete\s*=|"
    r"getElementById|querySelector|interface\s+\w+|type\s+\w+\s*=|password(?:Input|Field)|"
    r"setPassword|resetPassword|changePassword|validatePassword)"
)
PLACEHOLDERS = {
    "password",
    "passwd",
    "senha",
    "secret",
    "token",
    "changeme",
    "change_me",
    "example",
    "exemplo",
    "sample",
    "teste",
    "test",
    "dummy",
    "your_password",
    "your_secret",
    "your_token",
    "insert_here",
    "replace_me",
    "undefined",
    "null",
    "true",
    "false",
    "xxxx",
    "xxxxx",
    "******",
}
IGNORED_EMAIL_DOMAINS = {"example.com", "example.org", "example.net", "teste.com", "email.com"}


@dataclass(frozen=True)
class TextResource:
    url: str
    text: str


def only_digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def valid_cpf(value: str) -> bool:
    digits = only_digits(value)
    if len(digits) != 11 or digits == digits[0] * 11:
        return False
    for size in (9, 10):
        total = sum(int(digits[index]) * (size + 1 - index) for index in range(size))
        check = (total * 10 % 11) % 10
        if check != int(digits[size]):
            return False
    return True


def valid_cnpj(value: str) -> bool:
    digits = only_digits(value)
    if len(digits) != 14 or digits == digits[0] * 14:
        return False
    for length, weights in (
        (12, (5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2)),
        (13, (6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2)),
    ):
        total = sum(
            int(digit) * weight for digit, weight in zip(digits[:length], weights, strict=True)
        )
        check = 0 if total % 11 < 2 else 11 - total % 11
        if check != int(digits[length]):
            return False
    return True


def valid_luhn(value: str) -> bool:
    digits = only_digits(value)
    if not 13 <= len(digits) <= 19 or digits == digits[0] * len(digits):
        return False
    total = 0
    parity = len(digits) % 2
    for index, digit in enumerate(map(int, digits)):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def plausible_secret_value(value: str) -> bool:
    normalized = value.strip().strip("'\"`.)")
    lowered = normalized.casefold()
    if len(normalized) < 6 or lowered in PLACEHOLDERS:
        return False
    if lowered.startswith(("process.env", "import.meta.env", "os.getenv", "getenv(", "config(")):
        return False
    if normalized.startswith(("${", "{{", "<%", "<", "$", "@")):
        return False
    if re.fullmatch(r"[A-Z_][A-Z0-9_]*", normalized) and "_" in normalized:
        return False
    character_classes = sum(
        bool(re.search(pattern, normalized)) for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^\w]")
    )
    return character_classes >= 2 or len(normalized) >= 16


def scan_resource(
    resource: TextResource,
    custom_words: tuple[str, ...] = (),
    context_chars: int = 1500,
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, int, int]] = set()
    line_starts = [0]
    line_starts.extend(match.end() for match in re.finditer(r"\n", resource.text))

    def add(
        indicator: str,
        category: str,
        severity: str,
        confidence: str,
        match: re.Match[str],
        start: int | None = None,
        end: int | None = None,
    ) -> None:
        absolute_start = match.start() if start is None else start
        absolute_end = match.end() if end is None else end
        key = (indicator, absolute_start, absolute_end)
        if key in seen:
            return
        seen.add(key)
        snippet_start = max(0, absolute_start - context_chars)
        snippet_end = min(len(resource.text), absolute_end + context_chars)
        raw_match = resource.text[absolute_start:absolute_end]
        snippet = resource.text[snippet_start:snippet_end]
        findings.append(
            Finding(
                severity=severity,  # type: ignore[arg-type]
                confidence=confidence,  # type: ignore[arg-type]
                category=category,
                indicator=indicator,
                url=resource.url,
                file_name=urlparse(resource.url).path.rstrip("/").rsplit("/", 1)[-1]
                or "(página)",
                line=bisect.bisect_right(line_starts, absolute_start),
                snippet=snippet,
                match_text=raw_match,
            )
        )

    for indicator, pattern, severity in KNOWN_SECRET_PATTERNS:
        for match in pattern.finditer(resource.text):
            add(indicator, "Segredo confirmado", severity, "confirmed", match)
    for match in PRIVATE_KEY_BLOCK_RE.finditer(resource.text):
        add("Private key", "Segredo confirmado", "critical", "confirmed", match)
    for match in DATABASE_CREDENTIAL_RE.finditer(resource.text):
        add("Database credentials", "Credencial", "critical", "confirmed", match)
    for match in SENSITIVE_ASSIGNMENT_RE.finditer(resource.text):
        inside_html_tag = resource.text.rfind("<", 0, match.start()) > resource.text.rfind(
            ">", 0, match.start()
        )
        context = resource.text[max(0, match.start() - 100) : match.end() + 100]
        if (inside_html_tag and NEGATIVE_CONTEXT_RE.search(context)) or not plausible_secret_value(
            match.group("value")
        ):
            continue
        add(f"Assignment: {match.group('key')}", "Credencial", "high", "high", match)
    for match in SENSITIVE_FILE_RE.finditer(resource.text):
        add("Sensitive file", "Arquivo sensível", "medium", "medium", match)
    for match in PRIVATE_PATH_RE.finditer(resource.text):
        add("Internal path", "Caminho interno", "medium", "medium", match)
    for match in INTERNAL_HOST_RE.finditer(resource.text):
        add("Internal host", "Infraestrutura interna", "medium", "medium", match)
    for match in CPF_RE.finditer(resource.text):
        nearby = resource.text[max(0, match.start() - 40) : match.end() + 40]
        if valid_cpf(match.group()) and ("." in match.group() or re.search(r"(?i)\bcpf\b", nearby)):
            add("CPF", "Dado pessoal", "high", "high", match)
    for match in CNPJ_RE.finditer(resource.text):
        nearby = resource.text[max(0, match.start() - 40) : match.end() + 40]
        if valid_cnpj(match.group()) and (
            "/" in match.group() or re.search(r"(?i)\bcnpj\b", nearby)
        ):
            add("CNPJ", "Dado pessoal", "medium", "high", match)
    for match in CARD_RE.finditer(resource.text):
        nearby = resource.text[max(0, match.start() - 50) : match.end() + 50]
        has_context = bool(
            re.search(r"(?i)\b(card|cart[aã]o|credit|pan|card_number|numero_cartao)\b", nearby)
        )
        if valid_luhn(match.group()) and (
            has_context or " " in match.group() or "-" in match.group()
        ):
            add("Payment card", "Dado pessoal", "critical", "high", match)
    for match in RG_CONTEXT_RE.finditer(resource.text):
        add(
            "RG",
            "Dado pessoal",
            "medium",
            "medium",
            match,
            match.start("value"),
            match.end("value"),
        )
    for match in EMAIL_RE.finditer(resource.text):
        domain = match.group().rsplit("@", 1)[-1].lower()
        token_start = max(
            resource.text.rfind(" ", 0, match.start()),
            resource.text.rfind("\n", 0, match.start()),
            resource.text.rfind('"', 0, match.start()),
            resource.text.rfind("'", 0, match.start()),
        ) + 1
        prefix_token = resource.text[token_start : match.start()]
        if domain not in IGNORED_EMAIL_DOMAINS and "://" not in prefix_token:
            add("Email address", "Dado pessoal", "low", "medium", match)
    for word in custom_words:
        for match in re.finditer(re.escape(word), resource.text, re.IGNORECASE):
            add(f"Custom: {word}", "Indicador personalizado", "informative", "low", match)
    return findings
