#!/usr/bin/make -f

# Makefile for xul-ext-monkeysphere

# © 2010 Jameson Rollins <jrollins@finestructure.net>
# Licensed under GPL v3 or later

xpi:
	git archive --format=zip --output=xul-ext-monkeysphere.xpi HEAD
