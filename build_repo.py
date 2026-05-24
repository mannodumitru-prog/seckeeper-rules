import os
import json
import hashlib
from datetime import datetime
from utils.osv_fetcher import fetch_osv_vulnerabilities

MANIFEST_FILE = "manifest.json"

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
            # 计算最新的哈希值
            file_hash = get_file_sha256(filename)
            # 读取规则内部自己的版本号
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


def transform_osv_to_seckeeper(osv_data):
    """
    将 OSV 复杂的 JSON 转换为您项目需要的精简格式
    """
    cve_id = osv_data.get('upstream', [osv_data.get('id')])[0] # 优先提取真实 CVE ID
    
    # 提取修复版本信息
    fixed_version = "unknown"
    for item in osv_data.get('affected', []):
        for range_item in item.get('ranges', []):
            for event in range_item.get('events', []):
                if 'fixed' in event:
                    fixed_version = event['fixed']
    
    # 映射为 SecKeeper 格式
    return {
        "cve_id": cve_id,
        "severity": "high", # 可以根据详情中的 urgency 字段进一步优化
        "description": osv_data.get('details', 'No description'),
        "fixed_version": fixed_version,
        "references": [ref['url'] for ref in osv_data.get('references', [])]
    }


def sync_cve_rules():
    print("🔄 开始从 OSV 获取最新 CVE 情报...")
    # 1. 抓取 (以 openssl 为例，您可以扩展到更多组件)
    raw_vulns = fetch_osv_vulnerabilities("openssl", ecosystem="Debian")
    new_rules = [transform_osv_to_seckeeper(v) for v in raw_vulns]
    
    # 2. 读取并合并现有规则
    rule_file = "cve_rules.json"
    with open(rule_file, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    existing_ids = {r['cve_id'] for r in data.get('rules', [])}
    added = 0
    for rule in new_rules:
        if rule['cve_id'] not in existing_ids:
            data['rules'].append(rule)
            existing_ids.add(rule['cve_id'])
            added += 1
            
    # 3. 更新 meta 信息
    data["meta"]["last_updated"] = datetime.now().strftime("%Y-%m-%d")
    data["meta"]["total_rules"] = len(data['rules'])
    
    # 4. 写回文件
    with open(rule_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print(f"✅ 完成合并，新增 {added} 条 CVE 规则。")



if __name__ == "__main__":
    # 1. 先进行漏洞数据库的自动扩充
    sync_cve_rules()
    
    # 2. 最后计算全库哈希并更新 manifest.json
    update_manifest()
