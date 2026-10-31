.PHONY: all test security regression demo install

install:
	pip install -q -r backend/requirements.txt flask

security:
	python tests/security

regression:
	python tests/regression

test: security regression

demo:
	python run_demo.py

all: test demo
