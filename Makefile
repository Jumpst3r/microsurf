SUBDIRS = $(shell ls -d binaries/*)


init:
	pip3 install -r requirements.txt
tests:
	pytest -sv --reruns 3
profile:
	python -m cProfile -o microsurf.pof microsurf/microsurf.py --binary binaries/secret1/secret-x86-32.bin --sc data
	snakeviz microsurf.pof
clean:
	rm *.pof *.png
binaries:
	for dir in $(SUBDIRS); do \
		make -C $$dir all; \
	done
.PHONY: init tests profile clean binaries