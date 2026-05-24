import requests
import json

def fetch_osv_vulnerabilities(package_name, ecosystem="Linux"):
    """
    通过 OSV.dev API 获取漏洞情报
    ecosystem 参数对于不同系统至关重要，例如 'Debian', 'Alpine', 'PyPI'
    """
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": ecosystem
        }
    }
    
    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            return response.json().get('vulns', [])
    except Exception as e:
        print(f"⚠️ OSV API 请求失败: {e}")
    return []

# 测试一下是否能获取到数据
if __name__ == "__main__":
    # 比如我们想关注 OpenSSL 的漏洞
    vulns = fetch_osv_vulnerabilities("openssl", ecosystem="Debian")
    print(f"✅ 成功获取到 {len(vulns)} 个漏洞条目")
    if vulns:
        print(json.dumps(vulns[0], indent=2))


if __name__ == "__main__":
    # 测试拉取 openssl 的漏洞，看看能不能拿到数据
    vulns = fetch_osv_vulnerabilities("openssl", ecosystem="Debian")
    print(f"Found {len(vulns)} vulnerabilities for openssl.")
    # 如果有数据，打印第一个看看结构
    if vulns:
        print(json.dumps(vulns[0], indent=2))
