from crops_security import database
from crops_security.core.findings import Finding


def test_delete_scan_removes_its_findings(monkeypatch, tmp_path) -> None:
    test_engine = database.create_database_engine(f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setattr(database, "engine", test_engine)
    database.initialize_database()

    scan = database.create_scan(
        "web.sensitive-data-finder",
        "https://app.example.test/",
        {"context_chars": 1500},
    )
    database.update_scan(scan["id"], status="completed")
    database.save_findings(
        scan["id"],
        (
            Finding(
                severity="high",
                confidence="high",
                category="Credencial",
                indicator="Assignment: password",
                url="https://app.example.test/app.js",
                file_name="app.js",
                line=14,
                snippet="\tpassword = ProductionSecret17\ncontexto posterior",
                match_text="password = ProductionSecret17",
            ),
        ),
    )

    stored_findings = database.list_findings(scan["id"])
    assert len(stored_findings) == 1
    assert stored_findings[0]["snippet"] == (
        "\tpassword = ProductionSecret17\ncontexto posterior"
    )
    assert stored_findings[0]["match_text"] == "password = ProductionSecret17"
    assert database.delete_scan(scan["id"]) is True
    assert database.get_scan(scan["id"]) is None
    assert database.list_findings(scan["id"]) == []

    test_engine.dispose()
