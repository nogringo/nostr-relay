#!/usr/bin/env perl

# Usage: embed-admin-assets.pl <output.h> <name>=<file> ...

use strict;
use warnings;

my $output = shift or die "usage: $0 <output.h> <name>=<file> ...\n";
my $delimiter = '__ADMIN_ASSET__';

my $header = "#pragma once\n\n#include <string_view>\n\n";

for my $arg (@ARGV) {
    my ($name, $file) = split /=/, $arg, 2;
    die "bad argument: $arg\n" unless defined $file;

    open(my $fh, '<:raw', $file) or die "unable to read $file: $!\n";
    my $content = do { local $/; <$fh> };
    close $fh;

    die "$file contains the raw string delimiter $delimiter\n" if index($content, ")$delimiter\"") >= 0;

    $header .= "static constexpr std::string_view $name = R\"$delimiter($content)$delimiter\";\n\n";
}

open(my $out, '>:raw', "$output.tmp") or die "unable to write $output.tmp: $!\n";
print $out $header;
close $out;
rename("$output.tmp", $output) or die "unable to rename $output.tmp: $!\n";
