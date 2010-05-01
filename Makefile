#!/usr/bin/make -f

# Makefile for xul-ext-monkeysphere

# © 2010 Jameson Rollins <jrollins@finestructure.net>
# Licensed under GPL v3 or later

XPI_CONTENTS:=$(shell find chrome modules defaults -name "*.html" -o -name "*.css" -o -name "*.png" -o -name "*.gif" -o -name "*.js" -o -name "*.jsm" -o -name "*.dtd" -o -name "*.xul" -o -name "messages") chrome.manifest install.rdf COPYING

ICONS = $(addprefix chrome/content/, bad.png error.png)
icons: $(ICONS)
%.png: %.svg
	inkscape --export-png $@ --export-area-page --export-background-opacity=0 $<

monkeysphere.xpi: $(XPI_CONTENTS) $(ICONS)
	zip $@ $(XPI_CONTENTS)

debian-package:
	git buildpackage -uc -us

publish: monkeysphere.xpi
	scp $< archivemaster@george.riseup.net:/srv/archive.monkeysphere.info/xul-ext/

clean:
	rm -f $(ICONS)
	rm -f monkeysphere.xpi

.PHONY: clean icons debian-package publish
