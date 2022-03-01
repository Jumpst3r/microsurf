init:
	pip3 install -r requirements.txt
tests:
	pytest -s
.PHONY: init tests