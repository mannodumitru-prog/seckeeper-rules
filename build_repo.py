"""
SecKeeper 中央规则仓库 - 情报熔炼与全量构建引擎
"""
import os
import json
import hashlib
import datetime
import requests
from cvss import CVSS3, CVSS2

# ==================== 1. 核心过滤与内务配置 ====================
TARGET_COMPONENTS = {
    "linux", "kernel", "openssh", "openssl", "sudo", "polkit", "policykit-1",
    "glibc", "libc6", "nginx", "docker", "docker.io", "containerd", "runc",
    "systemd", "bash", "curl", "libcurl4", "wget", "bind9", "dbus", "pam"
}
MIN_YEAR = 2016
MIN_CVSS_SCORE = 7.0
OSV_QUERY_API = "https://api.osv.dev/v1/query"

IGNORE_FILES = {'manifest.json', 'README.md', 'build_repo.py', '.gitignore', '.gitattributes'}
IGNORE_DIRS = {'.git', '.github', 'utils', '__pycache__'}

# ==================== 2. 工具辅助函数 ====================
def _get_cve_id(vuln_raw: dict):
    vuln_id = vuln_raw.get("id", "")
    if vuln_id.startswith("CVE-"): return vuln_id
    for alias in vuln_raw.get("aliases", []):
        if alias.startswith("CVE-"): return alias
    return None

def _is_in_time_range(vuln_raw: dict) -> bool:
    pub_str = vuln_raw.get("published")
    if not pub_str: return False
    try:
        return int(pub_str[:4]) >= MIN_YEAR
    except ValueError: return False

def _calculate_cvss(vuln_raw: dict):
    score = None
    for sev in vuln_raw.get("severity", []):
        try:
            vec = sev.get("score", "")
            if sev["type"] == "CVSS_V3" and vec.startswith("CVSS:3"):
                score = CVSS3(vec).scores()[0]
                break
            elif sev["type"] == "CVSS_V2":
                score = CVSS2(vec).scores()[0]
        except Exception: continue
    if score is None:
        db_spec = vuln_raw.get("database_specific", {})
        if isinstance(db_spec.get("cvss"), dict): score = db_spec["cvss"].get("score")
    try:
        if score is None or float(score) < MIN_CVSS_SCORE: return None, None
        return round(float(score), 1), ("critical" if float(score) >= 9.0 else "high")
    except (ValueError, TypeError): return None, None

def _parse_ranges(vuln_raw: dict) -> list:
    software_list = []
    for affected in vuln_raw.get("affected", []):
        pkg_name = affected.get("package", {}).get("name", "").lower()
        if pkg_name not in TARGET_COMPONENTS: continue
        for r in affected.get("ranges", []):
            if r.get("type") not in ("ECOSYSTEM", "SEMVER"): continue
            current_range = {"name": pkg_name}
            for event in r.get("events", []):
                if "introduced" in event:
                    ver = event["introduced"]
                    if ver != "0": current_range["version_start_including"] = ver
                elif "fixed" in event:
                    current_range["version_end_excluding"] = event["fixed"]
                    software_list.append(current_range.copy())
                    current_range = {"name": pkg_name}
            if len(current_range) > 1: software_list.append(current_range.copy())
    return [dict(t) for t in {tuple(sorted(d.items())) for d in software_list}]

def _gen_remediation(affected_list: list) -> str:
    fixes = [f"{i['name']} >= {i['version_end_excluding']}" for i in affected_list if "version_end_excluding" in i]
    return f"Upgrade components: {', '.join(list(set(fixes))[:3])}." if fixes else "Refer to vendor advisories."

# ==================== 3. 逻辑同步函数 ====================
def sync_cve_rules():
    rule_file = "cve_rules.json"
    existing_data = {"meta": {"version": "1.0.0", "total_rules": 0}, "rules": []}
    if os.path.exists(rule_file):
        try:
            with open(rule_file, "r", encoding="utf-8") as f: existing_data = json.load(f)
        except Exception: pass
    registry = {r["cve_id"]: r for r in existing_data.get("rules", [])}
    
    for pkg in TARGET_COMPONENTS:
        ecosystem = "Linux" if pkg in ("linux", "kernel") else "Debian"
        page_token = None
        while True:
            payload = {"package": {"name": pkg, "ecosystem": ecosystem}}
            if page_token: payload["page_token"] = page_token
            try:
                resp = requests.post(OSV_QUERY_API, json=payload, timeout=15)
                if resp.status_code != 200: break
                data = resp.json()
            except Exception: break
            for v in data.get("vulns", []):
                cve_id = _get_cve_id(v)
                if not cve_id or not _is_in_time_range(v): continue
                score, severity = _calculate_cvss(v)
                if not score: continue
                cleaned_software = _parse_ranges(v)
                if not cleaned_software: continue
                registry[cve_id] = {
                    "cve_id": cve_id, "severity": severity, "cvss_score": score,
                    "description": (v.get("summary") or "No description")[:300],
                    "affected_software": cleaned_software, "remediation": _gen_remediation(cleaned_software)
                }
            page_token = data.get("next_page_token")
            if not page_token: break

    existing_data["rules"] = list(registry.values())
    existing_data["meta"].update({"last_updated": datetime.datetime.now().strftime("%Y-%m-%d"), "total_rules": len(existing_data["rules"])})
    with open(rule_file, "w", encoding="utf-8") as f: json.dump(existing_data, f, indent=4, ensure_ascii=False)

def build_manifest():
    payloads_map = {}
    for root, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith('.')]
        for file in files:
            if file in IGNORE_FILES or file.startswith('.'): continue
            full_path = os.path.join(root, file)
            sha256 = hashlib.sha256()
            with open(full_path, "rb") as f:
                for b in iter(lambda: f.read(4096), b""): sha256.update(b)
            payloads_map[os.path.relpath(full_path, start=".").replace("\\", "/")] = {"version": "1.0.0", "sha256": sha256.hexdigest()}
    
    with open("manifest.json", "w", encoding="utf-8") as f:
        json.dump({"version": "1.0.1", "last_updated": datetime.datetime.now().isoformat(), "files": payloads_map}, f, indent=4, ensure_ascii=False)

if __name__ == "__main__":
    sync_cve_rules()
    build_manifest()
