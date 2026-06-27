import os, json, hashlib, re, io, zipfile, requests
from datetime import datetime
from cvss import CVSS3, CVSS2

TARGETS = {"linux", "kernel", "openssh", "openssl", "sudo", "polkit", "glibc", "libc6", "nginx", "docker", "systemd", "bash", "curl", "bind9", "dbus", "pam"}

# 谷歌云官方全量实时仓储（标准的 .zip 规范路径）
DUMP_ZIPS = [
    "https://storage.googleapis.com/osv-vulnerabilities/Linux/all.zip",
    "https://storage.googleapis.com/osv-vulnerabilities/Debian/all.zip",
    "https://storage.googleapis.com/osv-vulnerabilities/Alpine/all.zip"
]

def get_hash(fp):
    s = hashlib.sha256()
    with open(fp, "rb") as f:
        for b in iter(lambda: f.read(4096), b""): s.update(b)
    return s.hexdigest()

def update_manifest():
    old_v = "1.0.0"
    if os.path.exists("manifest.json"):
        try: old_v = json.load(open("manifest.json")).get("version", "1.0.0")
        except: pass
    p = old_v.split('.'); p[-1] = str(int(p[-1])+1); new_v = ".".join(p)
    info = {fn: {"version": json.load(open(fn)).get("meta",{}).get("version","1.0.0"), "sha256": get_hash(fn)} for fn in os.listdir(".") if fn.endswith("_rules.json") and fn != "manifest.json"}
    json.dump({"version": new_v, "last_updated": datetime.now().isoformat(), "files": info}, open("manifest.json", "w"), indent=4)
    print(f"✅ Manifest 已同步更新至: {new_v}")

def sync():
    print("🚀 启动云端仓储直连 | 正在高速载入谷歌云 Linux 全量压缩库...")
    raw_list = []
    for url in DUMP_ZIPS:
        eco = url.split("/")[-2]
        try:
            print(f"  -> 正在空中解压 [ {eco} ] 生态全量漏洞包...")
            r = requests.get(url, timeout=35)
            if r.status_code == 200:
                with zipfile.ZipFile(io.BytesIO(r.content)) as z:
                    for fn in z.namelist():
                        if fn.endswith(".json"): raw_list.append(json.loads(z.read(fn)))
        except Exception as e: print(f"     [!] 跳过 {eco}: {e}")
        
    print(f"📦 解压完毕！内存共载入原始记录 {len(raw_list)} 条。开始高危过筛...")
    
    reg = {}
    for v in raw_list:
        cve = next((c for c in v.get("upstream",[])+v.get("aliases",[])+[v.get("id","")] if re.search(r"CVE-(\d{4})-", str(c)) and int(re.search(r"CVE-(\d{4})-", str(c)).group(1))>=2016), None)
        if not cve: continue
        
        score = None
        for s in v.get("severity",[]):
            try:
                if s["type"]=="CVSS_V3" and s.get("score","").startswith("CVSS:3"): score = CVSS3(s["score"]).scores()[0]; break
                elif s["type"]=="CVSS_V2": score = CVSS2(s["score"]).scores()[0]
            except: pass
        if not score: score = v.get("database_specific",{}).get("cvss",{}).get("score") if isinstance(v.get("database_specific",{}).get("cvss"), dict) else None
        if not score and any(k in str(v).lower() for k in ["critical", "high severity", "urgency: high"]): score = 7.8
        if not score or float(score) < 7.0: continue
        
        soft = []
        for aff in v.get("affected",[]):
            pkg = aff.get("package",{}).get("name","").lower()
            if pkg not in TARGETS: continue
            for r in aff.get("ranges",[]):
                if r.get("type") not in ("ECOSYSTEM","SEMVER"): continue
                cur = {"name": pkg}
                for ev in r.get("events",[]):
                    if "introduced" in ev and ev["introduced"]!="0": cur["version_start_including"]=ev["introduced"]
                    elif "fixed" in ev: cur["version_end_excluding"]=ev["fixed"]; soft.append(cur.copy()); cur={"name":pkg}
                    elif "last_affected" in ev: cur["version_end_including"]=ev["last_affected"]; soft.append(cur.copy()); cur={"name":pkg}
                if len(cur)>1: soft.append(cur.copy())
        if not soft: continue
        
        uniq = []; [uniq.append(x) for x in soft if x not in uniq]
        reg[cve] = {"cve_id": cve, "severity": "critical" if float(score)>=9.0 else "high", "cvss_score": round(float(score),1), "description": (v.get("summary") or v.get("details") or "").strip().replace("\n"," ")[:300], "affected_software": uniq, "remediation": "Upgrade target components to fixed secure version."}

    rules = sorted(reg.values(), key=lambda x: x["cvss_score"], reverse=True)
    json.dump({"meta": {"version": "1.0.0", "total_rules": len(rules), "last_updated": datetime.now().strftime("%Y-%m-%d")}, "rules": rules}, open("cve_rules.json", "w"), indent=4, ensure_ascii=False)
    print(f"🎯 漏斗清洗大获全胜！存留 {len(rules)} 条精英规则，已写入 cve_rules.json")

if __name__ == "__main__":
    sync()
    update_manifest()
