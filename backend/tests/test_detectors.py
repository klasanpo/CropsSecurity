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


def test_detects_and_preserves_plausible_hardcoded_secret() -> None:
    secret = "Prod-Secret-92817"
    findings = scan_resource(
        TextResource("https://app.example.test/config.js", f'client_secret = "{secret}"')
    )

    assert [finding.indicator for finding in findings] == ["Assignment: client_secret"]
    assert findings[0].snippet == f'client_secret = "{secret}"'
    assert findings[0].match_text == f'client_secret = "{secret}"'


def test_detects_known_token_with_confirmed_confidence() -> None:
    token = "AKIAIOSFODNN7EXAMPLE"
    findings = scan_resource(TextResource("https://app.example.test/main.js", token))

    assert len(findings) == 1
    assert findings[0].indicator == "AWS access key"
    assert findings[0].confidence == "confirmed"
    assert findings[0].snippet == token
    assert findings[0].match_text == token


def test_preserves_private_key_material_in_evidence() -> None:
    key_material = "AABBCCDDEEFF00112233445566778899"
    findings = scan_resource(
        TextResource(
            "https://app.example.test/key.pem",
            f"-----BEGIN PRIVATE KEY-----\n{key_material}\n-----END PRIVATE KEY-----",
        )
    )

    assert [finding.indicator for finding in findings] == ["Private key"]
    assert key_material in findings[0].snippet
    assert findings[0].match_text == (
        f"-----BEGIN PRIVATE KEY-----\n{key_material}\n-----END PRIVATE KEY-----"
    )


def test_validates_brazilian_documents_before_reporting() -> None:
    findings = scan_resource(
        TextResource(
            "https://app.example.test/data.json",
            "CPF: 529.982.247-25\nCPF inválido: 529.982.247-24\n"
            "CNPJ: 04.252.011/0001-10\nCNPJ inválido: 04.252.011/0001-11",
        )
    )

    assert [finding.indicator for finding in findings] == ["CPF", "CNPJ"]
    assert findings[0].match_text == "529.982.247-25"
    assert findings[1].match_text == "04.252.011/0001-10"


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


def test_ignores_environment_references_and_template_expressions() -> None:
    text = """
    password = process.env.DATABASE_PASSWORD
    api_key = ${API_KEY}
    client_secret = DATABASE_CLIENT_SECRET
    token = {{ vault_token }}
    """

    assert indicators(text) == set()


def test_detects_rg_internal_hosts_and_windows_paths() -> None:
    findings = scan_resource(
        TextResource(
            "https://app.example.test/data.txt",
            r"RG: 12.345.678-9 backend=192.168.10.25 root=C:\inetpub\wwwroot\portal",
        )
    )

    assert {finding.indicator for finding in findings} == {"RG", "Internal host", "Internal path"}
    assert next(finding for finding in findings if finding.indicator == "RG").match_text == (
        "12.345.678-9"
    )


def test_preserves_whitespace_without_normalizing_evidence() -> None:
    source = '\tclient_secret = "Production-Secret-4839"\n'
    findings = scan_resource(TextResource("https://app.example.test/config.js", source))

    assert findings[0].snippet == source
    assert findings[0].match_text == 'client_secret = "Production-Secret-4839"'


def test_ignores_email_embedded_in_url_credentials() -> None:
    assert indicators("https://admin@corp.example.test/private") == set()


def test_preserves_large_context_on_both_sides_by_default() -> None:
    prefix = "A" * 2000
    suffix = "B" * 2000
    findings = scan_resource(
        TextResource(
            "https://app.example.test/config.js",
            f'{prefix}\nclient_secret = "Production-Secret-4839"\n{suffix}',
        )
    )

    assert findings[0].snippet.startswith("A" * 1499)
    assert findings[0].snippet.endswith("B" * 1499)
