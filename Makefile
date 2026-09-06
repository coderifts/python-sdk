.PHONY: test packed-install

# Fresh-venv reproduction (same as README Tests / CI).
test:
	python3 -m pip install -e '.[test]'
	pytest

# Built-wheel reproduction (what would be published, not the working tree).
packed-install:
	bash scripts/check-packed-install.sh
