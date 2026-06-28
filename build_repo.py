"""
SecKeeper 中央规则仓库 - 全量递归构建引擎
功能：深度遍历项目下所有规则、PoC、YAML，自动生成带有防篡改哈希的清单。
"""
import os
import json
import hashlib
import datetime

# 1. 严禁下发给客户端的“仓库内务文件”
IGNORE_FILES = {'manifest.json', 'README.md', 'build_repo.py', '.gitignore', '.gitattributes'}
IGNORE_DIRS = {'.git', '.github', 'utils', '__pycache__'}  # utils是发货端工具，不用发给客户

def get_sha256(filepath: str) -> str:
    """计算文件的标准 SHA256 哈希值"""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def build_manifest():
    manifest_path = "manifest.json"
    old_version = "1.0.0"

    # 读取旧版本号，实现版本号自动 +1 (例如 1.0.20 -> 1.0.21)
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                old_version = json.load(f).get("version", "1.0.0")
        except Exception:
            pass

    v_parts = old_version.split('.')
    if len(v_parts) == 3 and v_parts[2].isdigit():
        v_parts[2] = str(int(v_parts[2]) + 1)
        new_version = ".".join(v_parts)
    else:
        new_version = old_version

    payloads_map = {}

    # 深度递归遍历整个仓库
    for root, dirs, files in os.walk("."):
        # 原地过滤掉不需要进入的系统文件夹
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith('.')]

        for file in files:
            if file in IGNORE_FILES or file.startswith('.'):
                continue

            full_path = os.path.join(root, file)
            # 获取相对路径，例如: "pocs/CVE-2021-4034.py" 或 "cve_rules.json"
            rel_path = os.path.relpath(full_path, start=".")
            
            # 【核心铁律】将 Windows 的反斜杠 \ 强制抹平为 Linux 的正斜杠 /
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

    print(f"✅ 构建完成！新版本: v{new_version} | 共纳管载荷文件: {len(payloads_map)} 个")

if __name__ == "__main__":
    build_manifest()
