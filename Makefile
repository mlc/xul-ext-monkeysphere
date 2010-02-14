#!/usr/bin/make -f

# Makefile for xul-ext-monkeysphere

# © 2010 Jameson Rollins <jrollins@finestructure.net>
# Licensed under GPL v3 or later

xpi:
	git archive --format=zip --output=xul-ext-monkeysphere.xpi HEAD

debian-package:
	git buildpackage -uc -us --git-upstream-branch=master --git-debian-branch=debian

clean:
	rm xul-ext-monkeysphere.xpi