#!/usr/bin/env python3
import hashlib, json, glob, os

def get_sha256(file_path):
    return hashlib.sha256(open(file_path, 'rb').read()).hexdigest()

def sync_manifest():
    manifest_path = 'manifest.json' # 根据你的实际目录调整
    pocs_dir = 'pocs/*.py'
    
    with open(manifest_path, 'r') as f:
        manifest = json.load(f)
    
    # 转字典以便快速更新
    manifest_dict = {item['cve_id']: item for item in manifest}
    
    for py_file in glob.glob(pocs_dir):
        cve_id = os.path.basename(py_file).replace('.py', '')
        new_sha = get_sha256(py_file)
        
        if cve_id in manifest_dict:
            manifest_dict[cve_id]['sha256'] = new_sha
        else:
            manifest_dict[cve_id] = {'cve_id': cve_id, 'file': os.path.basename(py_file), 'sha256': new_sha}
            
    with open(manifest_path, 'w') as f:
        json.dump(list(manifest_dict.values()), f, indent=4)

if __name__ == "__main__":
    sync_manifest()
