#!/usr/bin/perl -w

# Copyright (C) 2013 Phillip Smith
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main;

use warnings;
use strict;
# The Perl convention for expressing version numbers as floats is:
#   version + (patch level / 1000).
use Getopt::Long;

my $VERSION = '%VERSION%';

# precompiled regex patterns
my $qr_ip4_address  = qr/(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/o;
my $qr_netfilter_log_line = qr/IN=(\S*) OUT=(\S*) (MAC=(\S*) )?SRC=(\S*) DST=(\S*) LEN=(\S*) .* PROTO=(\S*) SPT=(\S*) DPT=(\S*) .*/o;

if ( -t STDIN ) {
  # no stdin data?
  print "No data found on standard input\n";
  exit 1;
}

# once we get to here, we have stdin data to read
my @stdin = <STDIN>;
foreach ( @stdin ) {
  my $line = $_;
  chomp($_);

  # make sure this line (appears to be) valid netfilter log
  unless ( $line =~ $qr_netfilter_log_line ) {
    print "Bad line: $line\n";
    next;
  }

  # it looks good, get the individual parts from the regex match
  my $in = $1;
  my $out = $2;
  my $src = $5;
  my $dst = $6;
  my $proto = lc($8);
  my $spt = $9;
  my $dpt = $10;

  # ipv4 or ipv6?
  my $ipver = ( $src =~ $qr_ip4_address) ? '4' : '6';

  # now we have the information, we can build a husk rule
  my $rule = "accept ip $ipver";
  $rule .= " source address $src"       if ( defined($src) );
  $rule .= " destination address $dst"  if ( defined($dst) );
  $rule .= " protocol $proto"           if ( defined($proto) );
  $rule .= " source port $spt"          if ( defined($spt) );
  $rule .= " port $dpt"                 if ( defined($dpt) );
  print $rule."\n";
}

__END__

# vim: et:ts=2:sw=2
