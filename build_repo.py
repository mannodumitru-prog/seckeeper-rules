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

def build_manifest():
    payloads = {}
    for root, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        for file in files:
            if file.startswith('.'): continue
            if file in IGNORE_FILES: continue
            
            path = os.path.join(root, file).replace("\\", "/")
            # 【修复点】：显式添加 version 字段，使之符合消费端需求
            payloads[path] = {
                "version": "1.0.1", 
                "sha256": get_hash(os.path.join(root, file))
            }
    
    # 写入 manifest
    manifest_data = {
        "version": "1.0.1",
        "last_updated": str(datetime.now()),
        "files": payloads
    }
    with open("manifest.json", "w") as f:
        json.dump(manifest_data, f, indent=4)

if __name__ == "__main__":
    sync_and_build()
    build_manifest()
