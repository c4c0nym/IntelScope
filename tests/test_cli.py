import json

from intelscope.cli import main


def test_demo_json(capsys):
    assert main(["--demo", "--format", "json", "-q"]) == 0
    doc = json.loads(capsys.readouterr().out)
    verdicts = {r["ioc"]: r["verdict"] for r in doc["results"]}
    assert verdicts["198.51.100.23"] == "malicious"
    assert verdicts["http://update-check.cdn-delivery.test/payload/inv_2291.exe"] == "malicious"
    assert verdicts["secure-login-micros0ft.test"] == "suspicious"
    assert verdicts["192.0.2.10"] == "low"
    assert verdicts["intranet-portal.example"] == "unknown"
    assert verdicts["203.0.113.77"] == "benign"
    assert verdicts["8.8.8.8"] == "benign"
    # triage order: malicious first
    assert doc["results"][0]["verdict"] == "malicious"


def test_fail_on_exit_code():
    assert main(["--demo", "-q", "--format", "csv", "--fail-on", "malicious"]) == 1
    assert main(["--demo", "-q", "--format", "csv", "--fail-on", "malicious",
                 "8.8.8.8"]) == 0


def test_min_verdict_filters(capsys):
    main(["--demo", "-q", "--format", "json", "--min-verdict", "suspicious"])
    doc = json.loads(capsys.readouterr().out)
    assert {r["verdict"] for r in doc["results"]} == {"malicious", "suspicious"}


def test_writes_html_file(tmp_path):
    out = tmp_path / "report.html"
    assert main(["--demo", "-q", "-o", str(out)]) == 0
    assert "intelscope" in out.read_text(encoding="utf-8")


def test_no_providers_configured(capsys):
    assert main(["1.2.3.4", "--providers", "vt,abuseipdb", "-q"]) == 2
    assert "no providers available" in capsys.readouterr().err


def test_no_valid_indicators(capsys):
    assert main(["nonsense", "-q"]) == 2


def test_unknown_provider(capsys):
    assert main(["1.2.3.4", "--providers", "nope"]) == 2
    assert "unknown provider" in capsys.readouterr().err


def test_table_output_runs(capsys):
    assert main(["--demo", "-q"]) == 0
    out = capsys.readouterr().out
    assert "MALICIOUS" in out and "198.51.100.23" in out
