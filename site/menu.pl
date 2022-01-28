#!/usr/bin/env perl

use v5.10;
use strict;
use warnings;

my $page = shift or die 'missing page';
my $outtype = shift or die 'missing output type';
my @pages = ();

while (<>) {
	chomp;
	@pages = (@pages, $_);
}

my $did = 0;
for (@pages) {
	my ($href, $text) = m/^([^\s]*)\s*(.*)$/;

	if ($outtype eq 'gemini') {
		if ($href ne $page) {
			say "=> $href $text";
		}
	} else {
		if (!$did) {
			$did = 1;
		} else {
			print "| ";
		}

		if ($href eq $page) {
			print "$text ";
		} else {
			print "<a href='$href'>$text</a> ";
		}
	}
}

say "";
