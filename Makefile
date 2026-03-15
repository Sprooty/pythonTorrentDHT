.PHONY: build dist docs test clean

VERSION=`python setup.py -V`

build:
	python setup.py build

dist:
	python setup.py sdist

install: dist
	pip -V
	pip install --no-cache-dir --no-deps --upgrade --force-reinstall --find-links ./dist/btdht-${VERSION}.tar.gz btdht

uninstall:
	pip uninstall btdht || true

test:
	python -m pytest tests/ -v

test_cov:
	python -m pytest tests/ -v --cov=btdht --cov-report=term-missing

clean:
	rm -rf build dist btdht.egg-info
	find ./ -name '*.pyc' -delete
	find ./ -name '*~' -delete
	find ./ -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true

clean_all: clean
