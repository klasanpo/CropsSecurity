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
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
SENSITIVE_FILE_RE = re.compile(
    r"(?i)(?<![\w.-])(?:\.env(?:\.(?:production|prod|staging|local))?|wp-config\.php|"
    r"application\.(?:properties|ya?ml)|appsettings\.json|database\.ya?ml|"
    r"service-account\.json|credentials\.json|id_rsa|authorized_keys)(?![\w.-])"
)
PRIVATE_PATH_RE = re.compile(
    r"(?i)(?<![\w.])(?:/(?:var/www|usr/share/nginx|usr/local/apache2|etc/(?:nginx|apache2|httpd|passwd|shadow)|"
    r"var/log/(?:nginx|apache2|httpd)|opt/(?:tomcat|[\w.-]+)|srv/www|root|usr/src/app|run/secrets|"
    r"var/run/(?:secrets/kubernetes\.io|docker\.sock)|etc/kubernetes)(?:/[\w.@+ -]+)*)"
)
EMAIL_RE = re.compile(r"(?i)(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}(?![\w.-])")
CPF_RE = re.compile(r"(?<!\d)(?:\d{3}\.\d{3}\.\d{3}-\d{2}|\d{11})(?!\d)")
CNPJ_RE = re.compile(r"(?<!\d)(?:\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}|\d{14})(?!\d)")
CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
NEGATIVE_CONTEXT_RE = re.compile(
    r"(?i)(?:<input\b|type\s*=\s*['\"]password|<label\b|placeholder\s*=|autocomplete\s*=|"
    r"getElementById|querySelector|interface\s+\w+|password(?:Input|Field)|setPassword|"
    r"resetPassword|changePassword|validatePassword)"
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
    normalized = value.strip("'\"`).").lower()
    if normalized in PLACEHOLDERS or normalized.startswith(("${", "{{", "<%")):
        return False
    if len(set(normalized)) <= 2:
        return False
    return any(character.isdigit() for character in normalized) or len(normalized) >= 8


def mask_value(value: str) -> str:
    if len(value) <= 7:
        return "***"
    return f"{value[:3]}…{value[-2:]}"


def scan_resource(resource: TextResource, custom_words: tuple[str, ...] = ()) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, int, str]] = set()
    lines = resource.text.splitlines()

    def add(
        indicator: str,
        category: str,
        severity: str,
        confidence: str,
        line_no: int,
        match: re.Match[str],
    ) -> None:
        key = (indicator, line_no, match.group(0))
        if key in seen:
            return
        seen.add(key)
        raw = match.group(0)
        line = lines[line_no - 1]
        start = max(0, match.start() - 90)
        end = min(len(line), match.end() + 90)
        snippet = line[start:end].strip()
        findings.append(
            Finding(
                severity=severity,  # type: ignore[arg-type]
                confidence=confidence,  # type: ignore[arg-type]
                category=category,
                indicator=indicator,
                url=resource.url,
                file_name=urlparse(resource.url).path.rsplit("/", 1)[-1] or "(página)",
                line=line_no,
                snippet=snippet.replace(raw, mask_value(raw)),
                match_text=mask_value(raw),
            )
        )

    for line_no, line in enumerate(lines, start=1):
        for indicator, pattern, severity in KNOWN_SECRET_PATTERNS:
            for match in pattern.finditer(line):
                add(indicator, "Segredo confirmado", severity, "confirmed", line_no, match)
        for match in PRIVATE_KEY_RE.finditer(line):
            add("Private key", "Segredo confirmado", "critical", "confirmed", line_no, match)
        for match in DATABASE_CREDENTIAL_RE.finditer(line):
            add("Database credentials", "Credencial", "critical", "confirmed", line_no, match)
        for match in SENSITIVE_ASSIGNMENT_RE.finditer(line):
            context = line[max(0, match.start() - 80) : match.end() + 80]
            if NEGATIVE_CONTEXT_RE.search(context) or not plausible_secret_value(
                match.group("value")
            ):
                continue
            add(f"Assignment: {match.group('key')}", "Credencial", "high", "high", line_no, match)
        for match in SENSITIVE_FILE_RE.finditer(line):
            add("Sensitive file", "Arquivo sensível", "medium", "medium", line_no, match)
        for match in PRIVATE_PATH_RE.finditer(line):
            add("Internal path", "Caminho interno", "medium", "medium", line_no, match)
        for match in CPF_RE.finditer(line):
            nearby = line[max(0, match.start() - 30) : match.end() + 30]
            if valid_cpf(match.group()) and (
                "." in match.group() or re.search(r"(?i)\bcpf\b", nearby)
            ):
                add("CPF", "Dado pessoal", "high", "high", line_no, match)
        for match in CNPJ_RE.finditer(line):
            nearby = line[max(0, match.start() - 30) : match.end() + 30]
            if valid_cnpj(match.group()) and (
                "/" in match.group() or re.search(r"(?i)\bcnpj\b", nearby)
            ):
                add("CNPJ", "Dado pessoal", "high", "high", line_no, match)
        for match in CARD_RE.finditer(line):
            nearby = line[max(0, match.start() - 35) : match.end() + 35]
            has_context = bool(re.search(r"(?i)\b(card|cart[aã]o|credit)\b", nearby))
            if valid_luhn(match.group()) and (
                has_context or " " in match.group() or "-" in match.group()
            ):
                add("Payment card", "Dado pessoal", "critical", "high", line_no, match)
        for match in EMAIL_RE.finditer(line):
            domain = match.group().rsplit("@", 1)[-1].lower()
            if domain not in IGNORED_EMAIL_DOMAINS:
                add("Email address", "Dado pessoal", "low", "medium", line_no, match)
        for word in custom_words:
            for match in re.finditer(re.escape(word), line, re.IGNORECASE):
                add(
                    f"Custom: {word}",
                    "Indicador personalizado",
                    "informative",
                    "low",
                    line_no,
                    match,
                )
    return findings
