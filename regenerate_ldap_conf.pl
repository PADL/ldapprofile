#!/usr/bin/perl
# @(#)regenerate_ldap_conf.pl
#
# Copyright (c) 2001 PADL Software Pty Ltd. All rights reserved.
# See COPYING for license terms.
#
# read /etc/ldap.conf, contact the profile
# server, and regenerate it
# NOT TESTED -- USE AT YOUR OWN RISK
#
if (open(LDAPCONF, "/etc/ldap.conf") == 0) {
	print STDERR "regenerate_ldap_conf.pl: could not find /etc/ldap.conf\n";
	exit 1;
}

while(<LDAPCONF>) {
	chop;
	if (s/^# Profile base: //) {
		$PROFILE_BASE = $_;
	} elsif (s/^# Profile host: //) {
		$PROFILE_HOST = $_;
	} elsif (s/^# Profile name: //) {
		$PROFILE_NAME = $_;
	}
}
close(LDAPCONF);

if ($PROFILE_HOST eq "") {
	print STDERR "regenerate_ldap_conf.pl: could not find profile host\n";
	exit 2;
}

if ($PROFILE_BASE eq "") {
	print STDERR "regenerate_ldap_conf.pl: could not find profile base\n";
	exit 3;
}

push (@LDAPCONFIG, "ldapprofile");

if ($ARGV[0] eq "-D") {
	push(@LDAPCONFIG, "-D");
}

if ($PROFILE_NAME ne "") {
	push (@LDAPCONFIG, "-p");
	push (@LDAPCONFIG, "\"$PROFILE_NAME\"");
}

push (@LDAPCONFIG, "-h");
push (@LDAPCONFIG, "\"$PROFILE_HOST\"");

push (@LDAPCONFIG, "-b");
push (@LDAPCONFIG, "\"$PROFILE_BASE\"");

$cmdline = join(' ', @LDAPCONFIG);

if ($PROFILE_NAME ne "") {
	print "Regenerating LDAP configuration profile $PROFILE_NAME from $PROFILE_BASE on host $PROFILE_HOST\n";
} else {
	print "Regenerating LDAP configuration profile from $PROFILE_BASE on host $PROFILE_HOST\n";
}

if ((system("$cmdline > /tmp/ldap.conf.$$") % 256) != 0) {
	print STDERR "regenerate_ldap_conf.pl: could not regenerate profile\n";
	exit 4;
}

if (rename("/tmp/ldap.conf.$$", "/etc/ldap.conf") == 0) {
	print STDERR "regenerate_ldap_conf.pl: could not move /tmp/ldap.conf.$$ to /etc/ldap.conf\n";
	exit 5;
}

