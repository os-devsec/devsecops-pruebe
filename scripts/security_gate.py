#!/usr/bin/env python3
"""Security Gate: agrega resultados de Snyk (Open Source + Code) y aplica
la politica definida en security-policy.json.

Uso:
    python scripts/security_gate.py snyk-oss.json snyk-code.json [reporte.md]

Exit code: 0 = PASS, 1 = FAIL.
"""
import json
import os
import sys

POLICY_PATH = os.environ.get("SECURITY_POLICY_PATH", "security-policy.json")

SECRET_KEYWORDS = (
    "secret",
    "credential",
    "api key",
    "apikey",
    "api_key",
    "password",
    "passwd",
    "hardcoded",
    "private key",
    "access key",
    "bearer token",
)

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def load_json(path: str) -> dict:
    try:
        # utf-8-sig tolera el BOM que algunos editores/shells (p.ej. PowerShell)
        # agregan al escribir JSON en Windows.
        with open(path, encoding="utf-8-sig") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def load_policy() -> dict:
    with open(POLICY_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def normalize_severity(raw) -> str:
    s = (raw or "").lower()
    if s in ("critical",):
        return "critical"
    if s in ("high", "error"):
        return "high"
    if s in ("medium", "warning"):
        return "medium"
    if s in ("low", "info", "note"):
        return "low"
    return "high"  # desconocido -> estricto


def parse_oss(data: dict) -> list[dict]:
    findings = []
    for v in data.get("vulnerabilities", []) or []:
        upgrade = " -> ".join(v.get("upgradePath", []) or [])
        findings.append(
            {
                "source": "SCA / Open Source",
                "severity": normalize_severity(v.get("severity")),
                "title": v.get("title", "?"),
                "package": v.get("packageName", "?"),
                "vuln": v.get("id", "?"),
                "where": f"{v.get('packageName')}@{v.get('version')}",
                "fix": upgrade or v.get("fix", ""),
            }
        )
    return findings


def parse_code(data: dict) -> list[dict]:
    findings = []

    # Formato SARIF (snyk code test --json)
    for run in data.get("runs", []) or []:
        driver = (run.get("tool", {}) or {}).get("driver", {}) or {}
        rules = {}
        for rule in driver.get("rules", []) or []:
            rules[rule.get("id")] = rule

        for res in run.get("results", []) or []:
            rule_id = res.get("ruleId", "?")
            rule = rules.get(rule_id, {})
            props = rule.get("properties", {}) or {}
            sev = normalize_severity(
                props.get("issueSeverity") or res.get("level")
            )
            msg = (res.get("message", {}) or {}).get("text", "") or ""
            loc = "?"
            for l in res.get("locations", []) or []:
                pl = l.get("physicalLocation", {}) or {}
                uri = ((pl.get("artifactLocation", {}) or {}).get("uri", "?"))
                line = ((pl.get("region", {}) or {}).get("startLine", "?"))
                loc = f"{uri}:{line}"
                break
            findings.append(
                {
                    "source": "SAST / Snyk Code",
                    "severity": sev,
                    "title": (msg[:140] or rule_id),
                    "package": rule_id,
                    "vuln": rule_id,
                    "where": loc,
                    "fix": props.get("recommendation", ""),
                }
            )

    # Formato alternativo ("suggestions")
    for sug in data.get("suggestions", []) or []:
        markers = sug.get("markers", []) or []
        files = "|".join(m.get("file", "?") for m in markers[:3]) or "?"
        findings.append(
            {
                "source": "SAST / Snyk Code",
                "severity": normalize_severity(sug.get("severity")),
                "title": sug.get("title") or sug.get("message", "?"),
                "package": sug.get("id", "?"),
                "vuln": sug.get("id", "?"),
                "where": files,
                "fix": "",
            }
        )
    return findings


def is_secret(f: dict) -> bool:
    hay = " ".join(str(f[k]).lower() for k in ("title", "package", "vuln"))
    return any(kw in hay for kw in SECRET_KEYWORDS)


def build_report(fail, warn, secret, counts, decision) -> str:
    lines = [
        "# Resultado del Security Gate",
        "",
        f"**Veredicto:** {decision}",
        "",
        "Resumen: "
        f"SCA={counts['sca']} | SAST={counts['sast']} | Secretos={counts['secret']}",
        "",
        "## Bloquean (FAIL)",
        "",
        "| Severidad | Fuente | Problema | Paquete/Regla | Ubicacion | Fix |",
        "|---|---|---|---|---|---|",
    ]
    for f in fail:
        fix = f["fix"].replace("|", "/") or "-"
        lines.append(
            f"| {f['severity']} | {f['source']} | {f['title']} "
            f"| {f['package']} | {f['where']} | {fix} |"
        )
    if secret:
        lines.append("")
        lines.append("## Secretos detectados (FAIL siempre)")
        lines.append("")
        lines.append("| Severidad | Fuente | Problema | Ubicacion |")
        lines.append("|---|---|---|---|")
        for f in secret:
            lines.append(
                f"| {f['severity']} | {f['source']} | {f['title']} | {f['where']} |"
            )
    lines.append("")
    lines.append("## Avisos (no bloquean)")
    lines.append("")
    lines.append("| Severidad | Fuente | Problema | Paquete/Regla | Ubicacion |")
    lines.append("|---|---|---|---|---|")
    for f in warn:
        lines.append(
            f"| {f['severity']} | {f['source']} | {f['title']} "
            f"| {f['package']} | {f['where']} |"
        )
    return "\n".join(lines)


def main(argv) -> int:
    if len(argv) < 2:
        print("Uso: security_gate.py <snyk-oss.json> <snyk-code.json> [reporte.md]")
        return 2

    oss_path, code_path = argv[0], argv[1]
    report_path = argv[2] if len(argv) > 2 else "security-gate-report.md"

    oss = load_json(oss_path)
    code = load_json(code_path)
    policy = load_policy()

    sca_findings = parse_oss(oss)
    sast_findings = parse_code(code)
    findings = sca_findings + sast_findings

    fail_on = set(policy.get("sca", {}).get("fail_on", [])) | set(
        policy.get("sast", {}).get("fail_on", [])
    )

    secret = [f for f in findings if is_secret(f)]
    secret_ids = {f["vuln"] for f in secret}
    fail = [
        f
        for f in findings
        if f["severity"] in fail_on and f["vuln"] not in secret_ids
    ]
    fail_ids = {f["vuln"] for f in fail}
    warn = [
        f
        for f in findings
        if f["vuln"] not in fail_ids
        and f["vuln"] not in secret_ids
        and f["severity"] not in fail_on
    ]

    if secret:
        decision = "FAIL - se detectaron secretos expuestos (bloqueante)"
    elif fail:
        decision = "FAIL - hay vulnerabilidades criticas/altas"
    else:
        decision = "PASS"

    counts = {
        "sca": len(sca_findings),
        "sast": len(sast_findings),
        "secret": len(secret),
    }
    report = build_report(fail, warn, secret, counts, decision)
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(report)

    print(report)
    print("---")
    print(f"Security Gate: {decision}")
    return 1 if (fail or secret) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
