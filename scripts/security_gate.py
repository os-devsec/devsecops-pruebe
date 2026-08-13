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

# Marcas para detectar secretos en reglas de Snyk Code (rule id / mensaje).
SECRET_RULE_MARKERS = ("secret", "credential")
SECRET_STRONG_MARKERS = (
    "api key",
    "apikey",
    "access key",
    "private key",
    "bearer token",
    "authorization",
)

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def load_json(path: str) -> tuple[dict, bool]:
    """Carga JSON tolerando BOM (en Windows, PowerShell redirige a UTF-16).

    Devuelve (data, ok). ok=False si el archivo no existe, no es JSON valido,
    o la herramienta devolvio un objeto de error (p.ej. Snyk con exit != 0).
    """
    if not os.path.exists(path):
        return {}, False
    for enc in ("utf-8-sig", "utf-16", "latin-1"):
        try:
            with open(path, encoding=enc) as fh:
                data = json.load(fh)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(data, dict) and "error" in data and not (
            "vulnerabilities" in data or "runs" in data
        ):
            return {}, False
        return data, True
    return {}, False


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
    """Clasifica un hallazgo como secreto si la regla es de credenciales
    (p.ej. python/HardcodedNonCryptoSecret) o el mensaje senala una API key.

    No se clasifican como secretos los hallazgos genericos de 'password
    hardcodeado' (baja severidad), que se tratan como aviso normal.
    """
    rule = str(f.get("package", "")).lower()
    title = str(f.get("title", "")).lower()
    if any(m in rule for m in SECRET_RULE_MARKERS):
        return True
    return any(kw in title for kw in SECRET_STRONG_MARKERS)


def build_report(fail, warn, secret, counts, decision, scan_failed=()) -> str:
    lines = [
        "# Resultado del Security Gate",
        "",
        f"**Veredicto:** {decision}",
        "",
        "Resumen: "
        f"SCA={counts['sca']} | SAST={counts['sast']} | Secretos={counts['secret']}",
        "",
    ]
    if scan_failed:
        lines.append(
            "## ATENCION: no se pudieron capturar resultados de Snyk: "
            + ", ".join(scan_failed)
        )
        lines.append(
            "El gate falla porque no se pudo confirmar el estado de seguridad "
            "(fail-closed). Revisa el log del job."
        )
        lines.append("")
    lines.append("## Bloquean (FAIL)")
    lines.append("")
    lines.append("| Severidad | Fuente | Problema | Paquete/Regla | Ubicacion | Fix |")
    lines.append("|---|---|---|---|---|---|")
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

    oss, oss_ok = load_json(oss_path)
    code, code_ok = load_json(code_path)
    policy = load_policy()

    scan_failed = []
    if not oss_ok:
        scan_failed.append(os.path.basename(oss_path))
    if not code_ok:
        scan_failed.append(os.path.basename(code_path))

    sca_findings = parse_oss(oss) if oss_ok else []
    sast_findings = parse_code(code) if code_ok else []
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

    if scan_failed:
        decision = "FAIL - no se pudieron capturar resultados de Snyk"
    elif secret:
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
    report = build_report(fail, warn, secret, counts, decision, scan_failed)
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(report)

    print(report)
    print("---")
    print(f"Security Gate: {decision}")
    return 1 if (fail or secret or scan_failed) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
