import os
import json
import hashlib
from datetime import datetime

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

if __name__ == "__main__":
    update_manifest()
