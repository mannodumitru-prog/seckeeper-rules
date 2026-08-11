import os, json, hashlib, zipfile, io, requests, re
from datetime import datetime
from cvss import CVSS3, CVSS2

# 配置中心
TARGETS = {"linux", "kernel", "openssh", "openssl", "sudo", "polkit", "glibc", "nginx", "docker", "systemd", "bash", "curl", "bind9", "dbus", "pam"}
IGNORE_FILES = {'manifest.json', 'README.md', 'build_repo.py', '.gitignore', '.gitattributes'}
IGNORE_DIRS = {'.git', '.github', 'utils', '__pycache__'}
DUMP_ZIPS = [
    "https://storage.googleapis.com/osv-vulnerabilities/Linux/all.zip",
    "https://storage.googleapis.com/osv-vulnerabilities/Debian/all.zip"
]

def get_hash(fp):
    s = hashlib.sha256()
    with open(fp, "rb") as f:
        for b in iter(lambda: f.read(4096), b""): s.update(b)
    return s.hexdigest()

def sync_and_build():
    print("🚀 启动严苛模式：执行高危情报熔炼...")
    raw_list = []
    for url in DUMP_ZIPS:
        try:
            r = requests.get(url, timeout=60)
            with zipfile.ZipFile(io.BytesIO(r.content)) as z:
                for fn in z.namelist():
                    if fn.endswith(".json"): raw_list.append(json.loads(z.read(fn)))
        except Exception as e: print(f"  [!] 获取失败: {e}")

    reg = {}
    for v in raw_list:
        # 严格筛选：CVE ID 必须存在且 >= 2016 年
        cve = next((c for c in v.get("aliases",[])+[v.get("id","")] if re.search(r"CVE-(\d{4})-", str(c))), None)
        if not cve or int(re.search(r"CVE-(\d{4})-", cve).group(1)) < 2016: continue
        
        # 严格筛选：只允许明确拥有 CVSS V3 分数的漏洞
        score = None
        for s in v.get("severity",[]):
            if s["type"] == "CVSS_V3" and "score" in s:
                try:
                    score = CVSS3(s["score"]).scores()[0]
                    break
                except: continue
        
        # 只有真正 >= 7.0 的高危漏洞才入库，拒绝任何模糊匹配
        if score is None or float(score) < 7.0: continue
        
        # 精准清洗：只有在 TARGETS 列表里的组件才会被记录
        affected_list = []
        for aff in v.get("affected", []):
            pkg_data = aff.get("package")
            if pkg_data and isinstance(pkg_data, dict):
                pkg_name = pkg_data.get("name")
                if pkg_name in TARGETS:
                    affected_list.append({"name": pkg_name})
        
        if not affected_list: continue # 如果漏洞不影响核心组件，则剔除
        
        reg[cve] = {
            "cve_id": cve, 
            "cvss_score": round(float(score), 1),
            "description": (v.get("summary") or v.get("details") or "")[:200],
            "affected_software": affected_list
        }
    
    # 写入规则库
    rules = sorted(reg.values(), key=lambda x: x["cvss_score"], reverse=True)
    with open("cve_rules.json", "w") as f:
        json.dump({"meta": {"total": len(rules), "updated": str(datetime.now())}, "rules": rules}, f, indent=4)
    print(f"🎯 熔炼完成！已精简至 {len(rules)} 条核心高危漏洞。")

ROOT_RULE_FILES = {
    "cve_rules.json",
    "file_integrity_rules.json",
    "config_rules.json",
    "weak_password_rules.json",
    "service_rules.json",
    "privilege_escalation_rules.json",
    "threat_rules.json",
}

IGNORE_DIRS = {
    ".git",
    ".github",
    "utils",
    "__pycache__",
}


def build_manifest():
    # 1. 读取现有版本
    current_version = "1.0.0"

    if os.path.exists("manifest.json"):
        try:
            with open("manifest.json", "r", encoding="utf-8") as f:
                old_data = json.load(f)

            current_version = old_data.get("version", "1.0.0")
        except (OSError, json.JSONDecodeError, ValueError):
            pass

    # 2. 递增最后一位版本号
    try:
        version_parts = current_version.split(".")
        version_parts[-1] = str(int(version_parts[-1]) + 1)
        new_version = ".".join(version_parts)
    except (ValueError, IndexError):
        new_version = "1.0.1"

    payloads = {}

    for root, dirs, files in os.walk("."):
        # 必须原地修改 dirs，阻止 os.walk 进入排除目录
        dirs[:] = [
            directory
            for directory in dirs
            if directory not in IGNORE_DIRS
            and not directory.startswith(".")
        ]

        for filename in files:
            full_path = os.path.join(root, filename)

            # 生成不带 "./" 的规范相对路径
            relative_path = os.path.relpath(
                full_path,
                "."
            ).replace("\\", "/")

            path_parts = relative_path.split("/")
            suffix = os.path.splitext(filename)[1].lower()

            should_include = False

            # 根目录只允许明确列出的规则 JSON
            if (
                len(path_parts) == 1
                and relative_path in ROOT_RULE_FILES
            ):
                should_include = True

            # pocs 目录只允许直接存放的 Python PoC
            elif (
                len(path_parts) == 2
                and path_parts[0] == "pocs"
                and suffix == ".py"
            ):
                should_include = True

            # yaml_pocs 目录只允许直接存放的 YAML
            elif (
                len(path_parts) == 2
                and path_parts[0] == "yaml_pocs"
                and suffix in {".yaml", ".yml"}
            ):
                should_include = True

            if not should_include:
                continue

            payloads[relative_path] = {
                "version": new_version,
                "sha256": get_hash(full_path)
            }

    # 3. 写入 manifest
    manifest_data = {
        "version": new_version,
        "last_updated": datetime.now().isoformat(
            sep=" ",
            timespec="seconds"
        ),
        "files": dict(sorted(payloads.items()))
    }

    with open("manifest.json", "w", encoding="utf-8") as f:
        json.dump(
            manifest_data,
            f,
            ensure_ascii=False,
            indent=4
        )

    print(
        f"✅ 规则清单已构建，当前版本: {new_version}，"
        f"共纳入 {len(payloads)} 个文件。"
    )
    
if __name__ == "__main__":
    sync_and_build()
    build_manifest()
