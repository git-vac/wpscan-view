"""Normalize upstream JSON without claiming more certainty than it contains."""
import json
import re
import shlex
import unicodedata

MAX_INPUT = 16 * 1024 * 1024
CHOICES = {
    "vp": "Vulnerable-plugin candidates", "ap": "All-plugin enumeration",
    "p": "Popular-plugin enumeration", "vt": "Vulnerable-theme candidates",
    "at": "All-theme enumeration", "t": "Popular-theme enumeration",
    "tt": "Timthumbs", "cb": "Config backups", "dbe": "Database exports",
    "bf": "Backup folders", "u": "Users", "m": "Media",
}
VALUE_OPTIONS = {
    "--url", "--user-agent", "--api-token", "--enterprise-db-token", "--http-auth", "--wp-auth",
    "--cookie-string", "--cookie-jar", "--headers", "--proxy", "--proxy-auth", "--format", "-f", "--output", "-o",
    "--plugins-list", "--themes-list", "--config-file", "--passwords", "-P", "--usernames", "-U",
    "--detection-mode", "--plugins-detection", "--themes-detection", "--plugins-version-detection",
    "--themes-version-detection", "--exclude-content-based", "--exclude-vulns", "--request-timeout",
    "--connect-timeout", "--max-threads", "--throttle", "--wp-content-dir", "--wp-plugins-dir",
}


def clean(value):
    """Remove terminal controls, including ESC, C1 and bidi formatting controls."""
    text = str(value) if value is not None else "Unknown"
    return "".join(c for c in text if c in "\n\t" or not unicodedata.category(c).startswith("C"))


def scrub(value):
    if isinstance(value, dict):
        return {clean(k): ("[redacted]" if re.search(
            r"password|passwd|token|secret|authorization|cookie", str(k), re.I
        ) else scrub(v)) for k, v in value.items() if k not in {"command_line", "hostname", "trace"}}
    if isinstance(value, list):
        return [scrub(v) for v in value]
    return clean(value) if isinstance(value, str) else value


def mapping(value):
    return value if isinstance(value, dict) else {}


def sequence(value):
    return value if isinstance(value, list) else []


def read_json(stream):
    raw = stream.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise ValueError("Input exceeds 16 MiB; split the report or raise the limit in a reviewed copy.")
    try:
        result = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Expected WPScan JSON. Use wpscan --format json, or the scan subcommand.") from exc
    if not isinstance(result, dict) or not any(k in result for k in (
        "target_url", "effective_url", "scan_aborted", "version", "plugins", "main_theme"
    )):
        raise ValueError("Input is not a WPScan result object.")
    return result


def scope(command):
    if not command:
        return {"kind": "Unknown", "choices": [], "evidence": "Command line absent; findings cannot prove enumeration scope."}
    try:
        args = command if isinstance(command, list) else shlex.split(command)
    except ValueError:
        return {"kind": "Unknown", "choices": [], "evidence": "Command line could not be parsed."}
    found = False
    choices = []
    details = []
    skip = False
    for i, arg in enumerate(args):
        if skip:
            skip = False
            continue
        if arg == "--":
            break
        if arg in ("--plugins-list", "--themes-list", "--wp-auth", "--config-file") or arg.startswith(
            ("--plugins-list=", "--themes-list=", "--wp-auth=", "--config-file=")
        ):
            details.append("Custom lists, configuration or authenticated inventory may override effective enumeration.")
        if arg in VALUE_OPTIONS:
            skip = True
            continue
        raw = None
        if arg in ("-e", "--enumerate"):
            found = True
            raw = args[i + 1] if i + 1 < len(args) and not args[i + 1].startswith("-") else ""
        elif arg.startswith("--enumerate=") or (arg.startswith("-e") and not arg.startswith("--") and len(arg) > 2):
            found = True
            raw = arg.split("=", 1)[1] if arg.startswith("--") else arg[2:]
        if raw is not None:
            if not raw:
                details.append("Bare enumeration flag: WPScan-version defaults; exact effective choices not recorded.")
            else:
                for code in raw.split(","):
                    code = code.strip()
                    base = re.sub(r"\d.*$", "", code)
                    choices.append({"code": clean(code), "label": CHOICES.get(base, "Unrecognized selection")})
    details.append("Scope describes recorded CLI intent. WPScan config files can add or override options.")
    return {"kind": "Enumeration" if found else "Standard / no explicit enumeration", "choices": choices,
            "evidence": " ".join(dict.fromkeys(details))}


def normalize(raw, command=None):
    scan_scope = scope(command if command is not None else raw.get("command_line"))
    source = scrub(raw)
    api = mapping(source.get("vuln_api"))
    warnings = []
    if source.get("scan_aborted") or source.get("update_aborted"):
        warnings.append("Scan aborted: " + clean(source.get("scan_aborted") or source.get("update_aborted")))
    elif not source.get("stop_time"):
        warnings.append("Completion not recorded; this report may be incomplete.")
    errors = [clean(api[k]) for k in ("error", "http_error", "parse_error") if api.get(k)]
    if errors:
        warnings.append("Vulnerability data unavailable or incomplete: " + "; ".join(errors))
    elif not api:
        warnings.append("Vulnerability API coverage not recorded; zero listed advisories is not a clean bill of health.")
    if api.get("requests_remaining") == 0:
        warnings.append("API requests remaining is zero; some components may lack vulnerability data.")
    if source.get("excluded_vulnerabilities"):
        warnings.append("WPScan excluded some advisories; the report is filtered.")
    warnings.extend(clean(v) for v in sequence(source.get("response_status_codes_warnings")))

    components = []

    def add(kind, slug, data, role=""):
        data = mapping(data)
        version = mapping(data.get("version")) if kind != "WordPress" else data
        vulns = [mapping(v) for v in sequence(data.get("vulnerabilities"))]
        outdated = data.get("outdated")
        if kind == "WordPress" and data.get("status") in ("outdated", "latest"):
            outdated = data["status"] == "outdated"
        components.append({"kind": kind, "name": clean(slug), "role": role,
            "version": clean(version.get("number")), "version_confidence": version.get("confidence"),
            "outdated": outdated, "latest": clean(data.get("latest_version")),
            "status": "Reported advisories" if vulns else ("Data gap" if errors or not api else "None listed"),
            "vulnerabilities": vulns, "evidence": data})

    if isinstance(source.get("version"), dict):
        add("WordPress", "WordPress", source["version"])
    theme = mapping(source.get("main_theme"))
    if theme:
        add("Theme", theme.get("slug", "Active theme"), theme, "Active")
        for parent in sequence(theme.get("parents")):
            if isinstance(parent, dict):
                add("Theme", parent.get("slug", "Parent theme"), parent, "Parent")
    for kind, key in (("Plugin", "plugins"), ("Theme", "themes")):
        for slug, data in mapping(source.get(key)).items():
            existing = next((c for c in components if c["kind"] == kind and c["name"] == clean(slug)), None)
            if existing:
                # Main-theme data and enumeration can contain different evidence: retain both.
                existing["evidence"]["enumeration_evidence"] = data
                known = {json.dumps(v, sort_keys=True) for v in existing["vulnerabilities"]}
                existing["vulnerabilities"].extend(v for v in sequence(mapping(data).get("vulnerabilities"))
                    if isinstance(v, dict) and json.dumps(v, sort_keys=True) not in known)
                if existing["vulnerabilities"]:
                    existing["status"] = "Reported advisories"
            else:
                add(kind, slug, data, "Enumerated" if kind == "Theme" else "")
    components.sort(key=lambda c: (not bool(c["vulnerabilities"]), c["kind"], c["name"].casefold()))
    extras = {k: source[k] for k in ("users", "interesting_findings", "config_backups", "db_exports",
        "backup_folders", "timthumbs", "medias", "notice", "excluded_vulnerabilities") if source.get(k)}
    return {"schema": "wpscan-view/1", "target": clean(source.get("effective_url") or source.get("target_url")),
        "target_ip": clean(source.get("target_ip")), "scope": scan_scope, "warnings": warnings,
        "components": components, "extras": extras, "statistics": {k: source[k] for k in (
            "start_time", "stop_time", "elapsed", "requests_done", "cached_requests", "vuln_api") if k in source}}
