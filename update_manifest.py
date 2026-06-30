#!/usr/bin/env python3
import hashlib, json, glob, os

def get_sha256(file_path):
    return hashlib.sha256(open(file_path, 'rb').read()).hexdigest()

def sync_manifest():
    manifest_path = 'manifest.json'
    # 扫描目录下所有的 py 文件和 yaml 文件
    files_to_track = glob.glob('pocs/*.py') + glob.glob('yaml_pocs/*.yaml')
    
    if os.path.exists(manifest_path):
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
    else:
        manifest = {"version": "1.0.37", "last_updated": "", "files": {}}

    # 确保结构存在
    if "files" not in manifest:
        manifest["files"] = {}

    # 同步哈希值
    for file_path in files_to_track:
        # 将路径标准化为 manifest 中的 key 格式
        norm_path = file_path.replace('./', '')
        sha = get_sha256(file_path)
        
        if norm_path in manifest["files"]:
            manifest["files"][norm_path]["sha256"] = sha
        else:
            manifest["files"][norm_path] = {"version": "1.0.0", "sha256": sha}

    # 更新时间戳
    from datetime import datetime
    manifest["last_updated"] = datetime.now().isoformat()
    
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=4)
    print("Manifest updated successfully.")

if __name__ == "__main__":
    sync_manifest()
