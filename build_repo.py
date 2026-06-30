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
    print("🚀 启动自动化情报熔炼流水线...")
    raw_list = []
    # 1. 高速拉取与解压
    for url in DUMP_ZIPS:
        try:
            print(f"  -> 正在载入: {url.split('/')[-2]} 生态情报...")
            r = requests.get(url, timeout=60)
            with zipfile.ZipFile(io.BytesIO(r.content)) as z:
                for fn in z.namelist():
                    if fn.endswith(".json"): raw_list.append(json.loads(z.read(fn)))
        except Exception as e: print(f"  [!] 获取失败: {e}")

    # 2. 高危漏斗过滤
    reg = {}
    for v in raw_list:
        cve = next((c for c in v.get("aliases",[])+[v.get("id","")] if re.search(r"CVE-(\d{4})-", str(c))), None)
        if not cve or int(re.search(r"CVE-(\d{4})-", cve).group(1)) < 2016: continue
        
        score = None
        for s in v.get("severity",[]):
            try:
                if s["type"]=="CVSS_V3": score = CVSS3(s["score"]).scores()[0]
            except: pass
        if not score or float(score) < 7.0: continue
        
        # 【鲁棒性修改】：防御性编程处理缺失字段
        affected_list = []
        for aff in v.get("affected", []):
            pkg_data = aff.get("package")
            if pkg_data and isinstance(pkg_data, dict):
                pkg_name = pkg_data.get("name")
                if pkg_name in TARGETS:
                    affected_list.append({"name": pkg_name})
        
        reg[cve] = {
            "cve_id": cve, 
            "cvss_score": round(float(score), 1),
            "description": (v.get("summary") or v.get("details") or "")[:200],
            "affected_software": affected_list
        }
    
    # 3. 写入规则库
    rules = sorted(reg.values(), key=lambda x: x["cvss_score"], reverse=True)
    with open("cve_rules.json", "w") as f:
        json.dump({"meta": {"total": len(rules), "updated": str(datetime.now())}, "rules": rules}, f, indent=4)
    print(f"✅ 熔炼完成，存留 {len(rules)} 条高危情报。")

def build_manifest():
    payloads = {}
    for root, _, files in os.walk("."):
        for file in files:
            if file in IGNORE_FILES or file.startswith('.'): continue
            path = os.path.join(root, file).replace("\\", "/")
            payloads[path] = {"sha256": get_hash(path)}
    
    with open("manifest.json", "w") as f:
        json.dump({"version": "1.0.1", "files": payloads}, f, indent=4)
    print("✅ 全量清单指纹已更新。")

if __name__ == "__main__":
    sync_and_build()
    build_manifest()
