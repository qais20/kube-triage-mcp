from kube_triage_mcp.redact import redact


def test_redacts_common_secrets():
    log = "\n".join(
        [
            "connecting to postgres://app:hunter2@db:5432/shop",
            "Authorization: Bearer abcdef1234567890",
            "AWS key AKIAIOSFODNN7EXAMPLE loaded",
            "DB_PASSWORD=s3cr3t",
            'api_key: "zzz-123"',
            "token ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ]
    )
    out, n = redact(log)
    for leaked in ("hunter2", "abcdef1234567890", "AKIAIOSFODNN7EXAMPLE", "s3cr3t", "zzz-123", "ghp_aaaa"):
        assert leaked not in out
    assert n >= 6
    assert "postgres://app:[REDACTED]@db" in out


def test_leaves_normal_lines_alone():
    line = "GET /healthz 200 3ms"
    assert redact(line) == (line, 0)
