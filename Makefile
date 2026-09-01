.PHONY: test compile build verify clean

test:
	python3 -m unittest discover -s tests -v

compile:
	python3 -m py_compile src/awgctl/*.py src/awginstall/*.py tools/*.py install.py

build:
	mkdir -p dist
	python3 tools/build_release.py --output dist/awgctl.pyz
	python3 tools/build_manifest.py --artifact dist/awgctl.pyz --output dist/release.json --version $$(sed -n 's/^VERSION = "\(.*\)"/\1/p' src/awgctl/version.py)

verify: test compile build
	dist/awgctl.pyz version
	python3 install.py check

clean:
	rm -rf build dist
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
