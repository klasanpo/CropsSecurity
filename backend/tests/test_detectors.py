from crops_security.tools.web.sensitive_data.detectors import TextResource, scan_resource


def indicators(text: str) -> set[str]:
    findings = scan_resource(TextResource("https://app.example.test/app.js", text))
    return {finding.indicator for finding in findings}


def test_ignores_placeholders_and_password_form_fields() -> None:
    text = """
    const password = "changeme";
    <input type="password" name="password" placeholder="Password">
    const api_key = "example";
    """

    assert indicators(text) == set()


def test_detects_and_masks_plausible_hardcoded_secret() -> None:
    secret = "Prod-Secret-92817"
    findings = scan_resource(
        TextResource("https://app.example.test/config.js", f'client_secret = "{secret}"')
    )

    assert [finding.indicator for finding in findings] == ["Assignment: client_secret"]
    assert secret not in findings[0].snippet
    assert secret not in findings[0].match_text


def test_detects_known_token_with_confirmed_confidence() -> None:
    token = "AKIAIOSFODNN7EXAMPLE"
    findings = scan_resource(TextResource("https://app.example.test/main.js", token))

    assert len(findings) == 1
    assert findings[0].indicator == "AWS access key"
    assert findings[0].confidence == "confirmed"
    assert token not in findings[0].snippet


def test_validates_brazilian_documents_before_reporting() -> None:
    findings = scan_resource(
        TextResource(
            "https://app.example.test/data.json",
            "CPF: 529.982.247-25\nCPF inválido: 529.982.247-24\n"
            "CNPJ: 04.252.011/0001-10\nCNPJ inválido: 04.252.011/0001-11",
        )
    )

    assert [finding.indicator for finding in findings] == ["CPF", "CNPJ"]


def test_requires_luhn_valid_payment_card() -> None:
    findings = scan_resource(
        TextResource(
            "https://app.example.test/checkout.json",
            "cartão: 4111 1111 1111 1111\ncartão inválido: 4111 1111 1111 1112",
        )
    )

    assert [finding.indicator for finding in findings] == ["Payment card"]


def test_ignores_documentation_email_domains() -> None:
    assert indicators("support@example.com") == set()
    assert indicators("security@corp.example.test") == {"Email address"}


def test_custom_words_are_reported_as_informative() -> None:
    findings = scan_resource(
        TextResource("https://app.example.test/main.js", "InternalProjectOrion"),
        custom_words=("ProjectOrion",),
    )

    assert len(findings) == 1
    assert findings[0].severity == "informative"
    assert findings[0].indicator == "Custom: ProjectOrion"
