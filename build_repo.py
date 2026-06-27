import os
import json
import hashlib
import requests
from datetime import datetime
from cvss import CVSS3, CVSS2

MANIFEST_FILE = "manifest.json"

# ==================== 核心过滤配置 ====================
TARGET_COMPONENTS = {
    "linux", "kernel", "openssh", "openssl", "sudo", "polkit", "policykit-1",
    "glibc", "libc6", "nginx", "docker", "docker.io", "containerd", "runc",
    "systemd", "bash", "curl", "libcurl4", "wget", "bind9", "dbus", "pam"
}
MIN_YEAR = 2016        # 过滤2016年至今的漏洞
MIN_CVSS_SCORE = 7.0   # CVSS >= 7.0 高危门槛
OSV_QUERY_API = "https://api.osv.dev/v1/query"
# ===================================================


def get_file_sha256(filepath):
    """计算文件的 SHA256 哈希值"""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def update_manifest():
    # 1. 尝试读取旧的 manifest，获取旧版本号（如果没有，从 1.0.0 开始）
    old_version = "1.0.0"
    if os.path.exists(MANIFEST_FILE):
        try:
            with open(MANIFEST_FILE, "r", encoding="utf-8") as f:
                old_manifest = json.load(f)
                old_version = old_manifest.get("version", "1.0.0")
        except Exception:
            pass

    # 2. 自动递增版本号 (例如 1.0.0 -> 1.0.1)
    v_parts = old_version.split('.')
    v_parts[-1] = str(int(v_parts[-1]) + 1)
    new_version = ".".join(v_parts)

    # 3. 扫描当前目录下所有的规则文件
    files_info = {}
    for filename in os.listdir("."):
        if filename.endswith("_rules.json") and filename != MANIFEST_FILE:
            file_hash = get_file_sha256(filename)
            with open(filename, "r", encoding="utf-8") as f:
                rule_content = json.load(f)
                rule_version = rule_content.get("meta", {}).get("version", "1.0.0")
            
            files_info[filename] = {
                "version": rule_version,
                "sha256": file_hash
            }

    # 4. 生成全新的 manifest 结构
    new_manifest = {
        "version": new_version,
        "last_updated": datetime.now().isoformat(),
        "files": files_info
    }

    # 5. 覆写 manifest.json
    with open(MANIFEST_FILE, "w", encoding="utf-8") as f:
        json.dump(new_manifest, f, indent=4, ensure_ascii=False)
        
    print(f"✅ Manifest 已自动更新至版本: {new_version}")


# ==================== 移植注入的清洗辅助函数 ====================

def _get_cve_id(vuln_raw: dict):
    vuln_id = vuln_raw.get("id", "")
    if vuln_id.startswith("CVE-"):
        return vuln_id
    for alias in vuln_raw.get("aliases", []):
        if alias.startswith("CVE-"):
            return alias
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
            
    if score is None or score < MIN_CVSS_SCORE:
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

# ===============================================================


def sync_cve_rules():
    print(f"🔄 开始向 OSV 检索 {len(TARGET_COMPONENTS)} 个核心组件的高危情报...")
    
    rule_file = "cve_rules.json"
    existing_data = {"meta": {"version": "1.0.0", "total_rules": 0}, "rules": []}
    
    # 1. 优雅地加载现有本地库（兼容 GitOps 增量更新逻辑）
    if os.path.exists(rule_file):
        try:
            with open(rule_file, "r", encoding="utf-8") as f:
                existing_data = json.load(f)
        except Exception:
            pass

    # 将现有规则建立哈希映射，方便动态去重合并
    registry = {r["cve_id"]: r for r in existing_data.get("rules", [])}
    initial_count = len(registry)

    # 2. 遍历组件全量 API 拉取
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
                if not cve_id or not _is_in_time_range(v): continue
                
                score, severity = _calculate_cvss(v)
                if not score: continue
                
                cleaned_software = _parse_ranges(v)
                if not cleaned_software: continue

                desc = (v.get("summary") or v.get("details") or "No description").strip().replace("\n", " ")[:300]

                # 去重与软件区间合并逻辑
                if cve_id in registry:
                    combined = registry[cve_id]["affected_software"] + cleaned_software
                    seen = set()
                    deduped = []
                    for s in combined:
                        k = tuple(sorted(s.items()))
                        if k not in seen:
                            seen.add(k); deduped.append(s)
                    registry[cve_id]["affected_software"] = deduped
                else:
                    registry[cve_id] = {
                        "cve_id": cve_id,
                        "severity": severity,
                        "cvss_score": score,
                        "description": desc,
                        "affected_software": cleaned_software,
                        "remediation": _gen_remediation(cleaned_software)
                    }

            page_token = data.get("next_page_token")
            if not page_token: break

    # 3. 整理出库
    final_rules = list(registry.values())
    final_rules.sort(key=lambda x: x["cvss_score"], reverse=True) # 按高危分降序
    
    added_count = len(final_rules) - initial_count

    # 4. 封装回团队规范的 meta 数据包装体
    existing_data["rules"] = final_rules
    existing_data["meta"]["last_updated"] = datetime.now().strftime("%Y-%m-%d")
    existing_data["meta"]["total_rules"] = len(final_rules)

    with open(rule_file, "w", encoding="utf-8") as f:
        json.dump(existing_data, f, indent=4, ensure_ascii=False)
        
    print(f"✅ 完成情报同步！全库现存 {len(final_rules)} 条规则（净新增 {added_count} 条）。")


if __name__ == "__main__":
    # 1. 先进行漏洞数据库的自动扩充与清洗
    sync_cve_rules()
    
    # 2. 最后计算全库哈希并更新 manifest.json
    update_manifest()
