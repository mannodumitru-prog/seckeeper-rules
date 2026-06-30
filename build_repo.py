"""
SecKeeper 中央规则仓库 - 情报熔炼与全量构建引擎
功能：
1. 自动从 OSV 抓取最新漏洞，严格执行生态适配、CVSS >= 7.0 及 10年内高危筛选。
2. 深度遍历项目下所有规则、PoC、YAML，自动生成带有防篡改哈希的清单 (manifest.json)。
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
MIN_YEAR = 2016        # 筛选：2016年至今的漏洞 (10年内)
MIN_CVSS_SCORE = 7.0   # 筛选：CVSS >= 7.0 高危门槛
OSV_QUERY_API = "https://api.osv.dev/v1/query"

# 严禁下发给客户端的“仓库内务文件”
IGNORE_FILES = {'manifest.json', 'README.md', 'build_repo.py', '.gitignore', '.gitattributes'}
IGNORE_DIRS = {'.git', '.github', 'utils', '__pycache__'}

# ==================== 2. OSV 情报清洗辅助函数 ====================
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
    except ValueError:
        return False

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
        if isinstance(db_spec.get("cvss"), dict):
            score = db_spec["cvss"].get("score")
            
    # 【核心筛选逻辑】：拦截所有低于 7.0 或无分数的漏洞
    if score is None or float(score) < MIN_CVSS_SCORE:
        return None, None
        
    score = round(float(score), 1)
    return score, ("critical" if score >= 9.0 else "high")

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
                    current_range = {"name": pkg_name}
                    if ver != "0": current_range["version_start_including"] = ver
                elif "fixed" in event:
                    current_range["version_end_excluding"] = event["fixed"]
                    software_list.append(current_range.copy())
                    current_range = {"name": pkg_name}
                elif "last_affected" in event:
                    current_range["version_end_including"] = event["last_affected"]
                    software_list.append(current_range.copy())
                    current_range = {"name": pkg_name}
            if len(current_range) > 1:
                software_list.append(current_range.copy())
                
    unique = []
    seen = set()
    for item in software_list:
        k = tuple(sorted(item.items()))
        if k not in seen:
            seen.add(k)
            unique.append(item)
    return unique

def _gen_remediation(affected_list: list) -> str:
    fixes = [f"{i['name']} >= {i['version_end_excluding']}" for i in affected_list if "version_end_excluding" in i]
    if fixes: return f"Upgrade vulnerable components: {', '.join(list(set(fixes))[:3])}."
    return "Please refer to official Linux vendor security advisories for patches."

# ==================== 3. 核心：情报拉取与合并 ====================
def sync_cve_rules():
    rule_file = "cve_rules.json"
    existing_data = {"meta": {"version": "1.0.0", "total_rules": 0}, "rules": []}
    
    if os.path.exists(rule_file):
        try:
            with open(rule_file, "r", encoding="utf-8") as f:
                existing_data = json.load(f)
        except Exception: pass

    registry = {r["cve_id"]: r for r in existing_data.get("rules", [])}
    initial_count = len(registry)
    
    print(f"🔄 开始向 OSV 检索 {len(TARGET_COMPONENTS)} 个核心组件的情报，执行严苛过滤...")

    for pkg in TARGET_COMPONENTS:
        page_token = None
        # 【生态适配补丁】：Linux 内核走 Linux 生态，其余组件走 Debian 生态
        ecosystem = "Linux" if pkg in ("linux", "kernel") else "Debian"
        
        while True:
            payload = {
                "package": {
                    "name": pkg,
                    "ecosystem": ecosystem
                }
            }
            if page_token: payload["page_token"] = page_token
            try:
                resp = requests.post(OSV_QUERY_API, json=payload, timeout=15)
                # 大声报错机制
                if resp.status_code != 200: 
                    print(f"⚠️ 抓取 [{pkg}] 失败！OSV 拒绝请求:
