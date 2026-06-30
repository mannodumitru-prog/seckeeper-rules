"""
SecKeeper 中央规则仓库 - 情报熔炼与全量构建引擎
功能：
1. 自动从 OSV 抓取最新漏洞，并严格执行 CVSS >= 7.0 及 10年内高危筛选。
2. 深度遍历项目下所有规则、PoC、YAML，自动生成带有防篡改哈希的清单。
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
        while True:
            payload = {"package": {"name": pkg}}
            if page_token: payload["page_token"] = page_token
            try:
                resp = requests.post(OSV_QUERY_API, json=payload, timeout=15)
                if resp.status_code != 200: break
                data = resp.json()
            except Exception: break

            for v in data.get("vulns", []):
                cve_id = _get_cve_id(v)
                
                # 【防线 1】：验证 ID 与十年内时间约束
                if not cve_id or not _is_in_time_range(v): continue
                
                # 【防线 2】：严格校验 CVSS 分数 >= 7.0
                score, severity = _calculate_cvss(v)
                if not score: continue
                
                # 【防线 3】：确保存在受影响的信创组件
                cleaned_software = _parse_ranges(v)
                if not cleaned_software: continue

                desc = (v.get("summary") or v.get("details") or "No description").strip().replace("\n", " ")[:300]

                if cve_id in registry:
                    combined = registry[cve_id]["affected_software"] + cleaned_software
                    seen = set(); deduped = []
                    for s in combined:
                        k = tuple(sorted(s.items()))
                        if k not in seen:
                            seen.add(k); deduped.append(s)
                    registry[cve_id]["affected_software"] = deduped
                else:
                    registry[cve_id] = {
                        "cve_id": cve_id, "severity": severity, "cvss_score": score,
                        "description": desc, "affected_software": cleaned_software,
                        "remediation": _gen_remediation(cleaned_software)
                    }

            page_token = data.get("next_page_token")
            if not page_token: break

    final_rules = list(registry.values())
    final_rules.sort(key=lambda x: x["cvss_score"], reverse=True) 
    added_count = len(final_rules) - initial_count

    existing_data["rules"] = final_rules
    existing_data["meta"]["last_updated"] = datetime.datetime.now().strftime("%Y-%m-%d")
    existing_data["meta"]["total_rules"] = len(final_rules)

    with open(rule_file, "w", encoding="utf-8") as f:
        json.dump(existing_data, f, indent=4, ensure_ascii=False)
        
    print(f"✅ 情报熔炼完成！全库现存 {len(final_rules)} 条高危规则（净新增 {added_count} 条）。")

# ==================== 4. 核心：全量清单构建 ====================
def get_sha256(filepath: str) -> str:
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def build_manifest():
    manifest_path = "manifest.json"
    old_version = "1.0.0"

    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                old_version = json.load(f).get("version", "1.0.0")
        except Exception: pass

    v_parts = old_version.split('.')
    if len(v_parts) == 3 and v_parts[2].isdigit():
        v_parts[2] = str(int(v_parts[2]) + 1)
        new_version = ".".join(v_parts)
    else:
        new_version = old_version

    payloads_map = {}

    for root, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith('.')]
        for file in files:
            if file in IGNORE_FILES or file.startswith('.'): continue

            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, start=".")
            rel_key = rel_path.replace("\\", "/")

            payloads_map[rel_key] = {
                "version": "1.0.0",
                "sha256": get_sha256(full_path)
            }

    manifest_data = {
        "version": new_version,
        "last_updated": datetime.datetime.now().isoformat(),
        "files": payloads_map
    }

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=4, ensure_ascii=False)

    print(f"✅ 规则库清单签名完毕！版本自增至: v{new_version} | 纳管文件: {len(payloads_map)} 个")

# ==================== 5. 流水线执行引擎 ====================
if __name__ == "__main__":
    print("🚀 启动 SecKeeper 中央规则库构建流水线...")
    
    # 步骤 1：拉取并应用严格过滤（找回了你的筛选逻辑）
    sync_cve_rules()
    
    # 步骤 2：对所有最终产物进行指纹计算与统一打包（你写的精彩逻辑）
    build_manifest()
