#!/usr/bin/env python3
"""SecKeeper远端规则构建器：默认校验并生成manifest，--sync-osv才联网。"""

from __future__ import annotations
import argparse, hashlib, io, json, os, re, tempfile, zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

ROOT_RULE_FILES = {"cve_rules.json", "file_integrity_rules.json", "config_rules.json", "weak_password_rules.json", "service_rules.json", "privilege_escalation_rules.json", "threat_rules.json"}
IGNORE_DIRS = {".git", ".github", "utils", "__pycache__"}
OSV_DUMPS = ("https://storage.googleapis.com/osv-vulnerabilities/Linux/all.zip", "https://storage.googleapis.com/osv-vulnerabilities/Debian/all.zip")
TARGET_ALIASES = {
    "linux": "linux", "kernel": "linux", "linux_kernel": "linux", "openssh": "openssh",
    "openssl": "openssl", "sudo": "sudo", "polkit": "polkit", "glibc": "glibc",
    "nginx": "nginx", "docker": "docker", "docker.io": "docker", "systemd": "systemd",
    "bash": "bash", "curl": "curl", "bind9": "bind9", "bind": "bind9", "dbus": "dbus", "pam": "pam",
}
VERSION_FIELDS = {"version_start_including", "version_start_excluding", "version_end_including", "version_end_excluding", "version_start", "version_end"}
REQUIRED_CVE_FIELDS = {"cve_id", "cvss_score", "severity", "description", "affected_software", "remediation"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> Dict:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path}顶层必须是JSON对象")
    return value


def normalize_cve_id(values: Iterable[object]) -> Optional[str]:
    """从OSV ID/aliases提取标准CVE，禁止保留DEBIAN-CVE前缀。"""
    for value in values:
        match = re.search(r"CVE-(\d{4})-(\d+)", str(value), re.I)
        if match:
            return f"CVE-{match.group(1)}-{match.group(2)}"
    return None


def normalize_target(name: object) -> Optional[str]:
    return TARGET_ALIASES.get(str(name or "").strip().lower().replace(" ", "_"))


def comparable_version(value: object) -> Optional[str]:
    text = str(value or "").strip()
    if text == "0":
        return "0"
    if not text or text == "*" or re.fullmatch(r"[0-9a-f]{20,}", text, re.I):
        return None
    if not re.search(r"\d", text) or "unknown" in text.lower():
        return None
    return text


def extract_version_ranges(affected: Dict, target: str) -> List[Dict]:
    """只接受ECOSYSTEM/SEMVER范围，并要求存在明确结束边界。"""
    results: List[Dict] = []
    for range_info in affected.get("ranges", []) or []:
        if str(range_info.get("type", "")).upper() not in {"ECOSYSTEM", "SEMVER"}:
            continue
        current_start = "0"
        for event in range_info.get("events", []) or []:
            if "introduced" in event:
                current_start = comparable_version(event.get("introduced")) or "0"
            boundary = field = None
            if "fixed" in event:
                boundary, field = comparable_version(event.get("fixed")), "version_end_excluding"
            elif "limit" in event:
                boundary, field = comparable_version(event.get("limit")), "version_end_excluding"
            elif "last_affected" in event:
                boundary, field = comparable_version(event.get("last_affected")), "version_end_including"
            if not boundary:
                continue
            item = {"name": target, field: boundary}
            if current_start not in {"0", ""}:
                item["version_start_including"] = current_start
            results.append(item)
            current_start = boundary
    return list({json.dumps(item, sort_keys=True): item for item in results}.values())


def cvss3_score(items: Iterable[Dict]) -> Optional[float]:
    try:
        from cvss import CVSS3
    except ImportError as exc:
        raise RuntimeError("--sync-osv需要安装requests和cvss") from exc
    for item in items or []:
        if item.get("type") == "CVSS_V3" and item.get("score"):
            try:
                return round(float(CVSS3(item["score"]).scores()[0]), 1)
            except Exception:
                pass
    return None


def osv_to_rule(record: Dict, cutoff_year: int) -> Optional[Dict]:
    cve_id = normalize_cve_id(list(record.get("aliases", []) or []) + [record.get("id")])
    if not cve_id or int(cve_id.split("-")[1]) < cutoff_year:
        return None
    score = cvss3_score(record.get("severity", []))
    if score is None or score < 7.0:
        return None
    affected_software: List[Dict] = []
    for affected in record.get("affected", []) or []:
        package = affected.get("package") if isinstance(affected, dict) else None
        target = normalize_target((package or {}).get("name"))
        if target:
            affected_software.extend(extract_version_ranges(affected, target))
    if not affected_software:
        return None
    description = str(record.get("summary") or record.get("details") or "").strip()
    if not description:
        return None
    return {
        "cve_id": cve_id, "cvss_score": score, "severity": "critical" if score >= 9.0 else "high",
        "description": description[:1000], "affected_software": affected_software,
        "remediation": "请升级受影响组件至厂商发布的已修复安全版本，并结合发行版安全公告确认回移补丁状态。",
        "references": [x.get("url") for x in record.get("references", []) or [] if isinstance(x, dict) and x.get("url")][:10],
        "verification_method": "version_match", "verification_engine": "osv_version_range",
        "verification_safety": "version_probe", "offline_supported": True,
    }


def validate_cve_data(data: Dict, cutoff_year: Optional[int] = None) -> Tuple[bool, str]:
    rules = data.get("rules")
    if not isinstance(rules, list) or not rules:
        return False, "CVE库缺少非空rules数组"
    seen = set()
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            return False, f"规则{index}不是对象"
        missing = sorted(k for k in REQUIRED_CVE_FIELDS if rule.get(k) in (None, "", []))
        if missing:
            return False, f"规则{index}缺少字段:{','.join(missing)}"
        cve_id = str(rule.get("cve_id"))
        if not re.fullmatch(r"CVE-\d{4}-\d+", cve_id):
            return False, f"非标准CVE:{cve_id}"
        if cve_id in seen:
            return False, f"重复规则:{cve_id}"
        seen.add(cve_id)
        if cutoff_year and int(cve_id.split("-")[1]) < cutoff_year:
            return False, f"超出近10年窗口:{cve_id}"
        try:
            score = float(rule.get("cvss_score"))
        except (TypeError, ValueError):
            return False, f"{cve_id}缺少有效CVSS"
        if score < 7.0:
            return False, f"{cve_id}的CVSS低于7.0"
        affected = rule.get("affected_software")
        if not isinstance(affected, list) or not affected:
            return False, f"{cve_id}缺少受影响软件"
        for item in affected:
            if not isinstance(item, dict) or not item.get("name"):
                return False, f"{cve_id}受影响软件结构错误"
            if not any(item.get(field) not in (None, "") for field in VERSION_FIELDS):
                return False, f"{cve_id}缺少版本范围"
    return True, "ok"


def validate_repository(root: Path, cutoff_year: Optional[int] = None) -> None:
    valid, reason = validate_cve_data(load_json(root / "cve_rules.json"), cutoff_year)
    if not valid:
        raise ValueError(reason)
    for filename in sorted(ROOT_RULE_FILES - {"cve_rules.json"}):
        data = load_json(root / filename)
        if not isinstance(data.get("rules"), list) and not isinstance(data.get("weak_password_dict"), list):
            raise ValueError(f"{filename}缺少规则数组")
    for path in sorted((root / "pocs").glob("*.py")):
        compile(path.read_text(encoding="utf-8"), str(path), "exec")
    for path in sorted((root / "yaml_pocs").glob("*.y*ml")):
        text = path.read_text(encoding="utf-8")
        if "id:" not in text or "info:" not in text:
            raise ValueError(f"Nuclei模板结构错误:{path.name}")


def download_osv_records() -> List[Dict]:
    try:
        import requests
    except ImportError as exc:
        raise RuntimeError("--sync-osv需要安装requests") from exc
    records: List[Dict] = []
    for url in OSV_DUMPS:
        response = requests.get(url, timeout=120)
        response.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            for name in archive.namelist():
                if name.endswith(".json"):
                    value = json.loads(archive.read(name))
                    if isinstance(value, dict):
                        records.append(value)
    return records


def sync_osv(root: Path) -> int:
    cutoff_year = datetime.now(timezone.utc).year - 10
    path = root / "cve_rules.json"
    original = load_json(path)
    valid, reason = validate_cve_data(original, cutoff_year=None)
    if not valid:
        raise ValueError(f"同步前CVE库校验失败，拒绝更新:{reason}")
    by_id = {
        rule["cve_id"]: rule for rule in original["rules"]
        if int(rule["cve_id"].split("-")[1]) >= cutoff_year
    }
    removed = len(original["rules"]) - len(by_id)
    added = 0
    for record in download_osv_records():
        candidate = osv_to_rule(record, cutoff_year)
        if candidate and candidate["cve_id"] not in by_id:
            by_id[candidate["cve_id"]] = candidate
            added += 1
    if not added and not removed:
        print("ℹ️ OSV中没有可安全转换的新规则，CVE库保持不变。")
        return 0
    merged = dict(original)
    merged["rules"] = sorted(by_id.values(), key=lambda x: (-float(x["cvss_score"]), x["cve_id"]))
    meta = dict(merged.get("meta", {}))
    meta.update({"last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%d"), "total_rules": len(merged["rules"]), "filter": {"year_gte": cutoff_year, "cvss_v3_gte": 7.0}})
    merged["meta"] = meta
    valid, reason = validate_cve_data(merged, cutoff_year)
    if not valid:
        raise ValueError(f"OSV合并结果校验失败，拒绝覆盖:{reason}")
    fd, temp_name = tempfile.mkstemp(prefix=".cve_rules_", suffix=".tmp", dir=root)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(merged, handle, ensure_ascii=False, indent=4); handle.write("\n")
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name): os.unlink(temp_name)
    print(f"✅ 安全合并{added}条新规则，移除{removed}条超出近10年窗口的规则；其余既有规则未改写。")
    return added


def iter_payloads(root: Path):
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]
        for filename in files:
            path = Path(current) / filename; rel = path.relative_to(root).as_posix(); parts = rel.split("/")
            if len(parts) == 1 and rel in ROOT_RULE_FILES: yield rel, path
            elif len(parts) == 2 and parts[0] == "pocs" and path.suffix.lower() == ".py": yield rel, path
            elif len(parts) == 2 and parts[0] == "yaml_pocs" and path.suffix.lower() in {".yaml", ".yml"}: yield rel, path


def next_version(value: str) -> str:
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", str(value))
    if not match: return "1.0.1"
    a, b, c = map(int, match.groups()); return f"{a}.{b}.{c + 1}"


def count_rules(path: Path) -> int:
    if path.suffix.lower() in {".py", ".yaml", ".yml"}: return 1
    data = load_json(path)
    if isinstance(data.get("rules"), list): return len(data["rules"])
    if isinstance(data.get("weak_password_dict"), list): return len(data["weak_password_dict"])
    return 0


def build_manifest(root: Path) -> bool:
    path = root / "manifest.json"; old = load_json(path) if path.exists() else {"version": "1.0.0", "files": {}}
    payloads = list(sorted(iter_payloads(root))); hashes = {name: sha256_file(file) for name, file in payloads}
    old_hashes = {name: str(info.get("sha256", "")) for name, info in (old.get("files", {}) or {}).items() if isinstance(info, dict)}
    changed = hashes != old_hashes
    if not changed:
        print(f"ℹ️ 规则内容无变化，manifest版本保持{old.get('version', '1.0.0')}。")
        return False
    version = next_version(old.get("version", "1.0.0"))
    files = {}; breakdown = {}
    for name, file in payloads:
        amount = count_rules(file); breakdown[name] = amount
        files[name] = {"version": version, "sha256": hashes[name], "size": file.stat().st_size, "rule_count": amount}
    now = datetime.now(timezone.utc)
    manifest = {"version": version, "last_updated": now.strftime("%Y-%m-%d"), "generated_at": now.isoformat(timespec="seconds").replace("+00:00", "Z"), "update_url": "https://raw.githubusercontent.com/mannodumitru-prog/seckeeper-rules/main/", "rules_breakdown": breakdown, "total_rules": sum(breakdown.values()), "files": files}
    with path.open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, ensure_ascii=False, indent=4); handle.write("\n")
    print(f"✅ manifest已生成：版本{version}，{len(files)}个文件。")
    return changed


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--sync-osv", action="store_true"); parser.add_argument("--validate-only", action="store_true"); args = parser.parse_args()
    root = Path(__file__).resolve().parent; cutoff = datetime.now(timezone.utc).year - 10
    validate_repository(root, cutoff_year=None if args.sync_osv else cutoff)
    print(f"✅ 仓库结构校验通过：CVSS v3>=7.0，完整schema。")
    if args.validate_only: return 0
    if args.sync_osv:
        sync_osv(root)
        validate_repository(root, cutoff)
        print(f"✅ 近10年窗口校验通过：CVE年份>={cutoff}。")
    build_manifest(root); return 0


if __name__ == "__main__": raise SystemExit(main())
