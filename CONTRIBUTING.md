# Contributing

Issues and pull requests are welcome within the current support boundary:
Ubuntu 24.04 LTS amd64 on AWS Lightsail. Proposals for other distributions,
architectures, cloud providers, IPv6, or multiple interfaces should begin with
an issue and include a test strategy; they are not silently accepted as
best-effort compatibility.

Before opening a pull request:

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile src/awgctl/*.py src/awginstall/*.py tools/*.py install.py
python3 tools/build_release.py --output dist/awgctl.pyz
dist/awgctl.pyz version
```

Keep the implementation dependency-free, avoid `shell=True`, never query
AmneziaWG `I1`–`I5`, and add a failing test before changing behavior. Tests must
not print or commit VPN credentials. Do not weaken the Lightsail/nftables trust
boundary or modify unrelated Docker/system firewall rules.
