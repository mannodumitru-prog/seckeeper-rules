# SecKeeper Rules

SecKeeper远端规则仓库。仓库保存JSON检测规则、本地Python PoC、Nuclei YAML模板和供客户端校验的`manifest.json`。

## CVE筛选口径

- 时间范围：按运行年份动态计算`当前年份 - 10`，2026年对应`CVE年份 >= 2016`。
- 风险阈值：CVSS v3基础分`>= 7.0`，包含恰好7.0分的高危漏洞。
- 组件范围：Linux内核、OpenSSH、OpenSSL、sudo、polkit、glibc、Nginx、Docker、systemd、bash、curl、BIND、D-Bus、PAM等主机核心组件。
- 结构要求：标准`CVE-YYYY-NNNN`、CVSS、severity、description、remediation，以及至少一个带明确版本边界的`affected_software`条目。

## 自动化策略

- `Validate Rules and Update Manifest`：规则文件发生变化时先校验全库，再重建manifest。校验失败时工作流失败且不提交任何生成文件。
- `Safe Daily OSV Sync`：每天检查OSV候选情报。只增量合并能够完整转换为SecKeeper schema的新规则，不覆盖已有规则；网络、解析或全库校验失败时不写入CVE库。
- OSV的GIT commit范围不能直接与主机软件版本比较，因此不会被错误转换为版本规则。

## 本地校验

```bash
python build_repo.py --validate-only
python build_repo.py
```

联网执行保守OSV增量检查：

```bash
python -m pip install requests cvss
python build_repo.py --sync-osv
```

`manifest.json`由脚本生成，不应手工编辑。离线Python PoC属于可执行规则，只允许合并经过团队审核的脚本。
