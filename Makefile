#!/usr/bin/make -f

# Makefile for xul-ext-monkeysphere

# © 2010 Jameson Rollins <jrollins@finestructure.net>
# Licensed under GPL v3 or later

XPI_CONTENTS:=$(shell find chrome modules defaults -name "*.html" -o -name "*.css" -o -name "*.png" -o -name "*.gif" -o -name "*.js" -o -name "*.jsm" -o -name "*.dtd" -o -name "*.xul" -o -name "messages") chrome.manifest install.rdf COPYING

monkeysphere.xpi: $(XPI_CONTENTS)
	zip $@ $(XPI_CONTENTS)

debian-package:
	git buildpackage -uc -us

publish: monkeysphere.xpi
	scp $< archivemaster@george.riseup.net:/srv/archive.monkeysphere.info/xul-ext/

clean:
	rm -f monkeysphere.xpi

.PHONY: clean debian-package publish
