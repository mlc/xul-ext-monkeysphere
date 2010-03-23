#!/usr/bin/make -f

# Makefile for xul-ext-monkeysphere

# © 2010 Jameson Rollins <jrollins@finestructure.net>
# Licensed under GPL v3 or later

XPI_CONTENTS:=$(shell find chrome defaults -name "*.html" -o -name "*.css" -o -name "*.png" -o -name "*.gif" -o -name "*.js" -o -name "*.dtd" -o -name "*.xul" -o -name "messages") chrome.manifest install.rdf COPYING

monkeysphere.xpi: $(XPI_CONTENTS)
	zip $@ $(XPI_CONTENTS)

debian-package:
	git buildpackage -uc -us

clean:
	rm -f monkeysphere.xpi

.PHONY: clean debian-package
