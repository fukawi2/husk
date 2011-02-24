#!/usr/bin/perl -w

# Copyright (C) 2010 Phillip Smith
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

use warnings;
use strict;
#use 5.010_001;	# Need Perl version 5.10 for Coalesce operator (//)
use Config::Simple;		# To parse husk.conf
use Config::IniFiles;	# To parse here documents in hostgroups.conf
use Getopt::Long;

my $VERSION = '%VERSION%';

# runtime vars
my ($conf_file, $conf_dir, $iptables, $iptables_restore, $udc_prefix, $kw);
my $script_output;			# Boolean to generate script output or not
my $curr_chain;				# Name of current chain to append rules to
my $line_cnt = 0;			# Counter for line number (Needs to be globally scoped to use in multiple subs)
my $xzone_prefix = 'crs';	# Prefix for Cross-zone chain names
# Arrays and Hashes
my %interface;			# Interfaces Name to eth Mappings
my %addr_group;			# Hostgroups from hostgroups.conf
my @output_rules;		# Compiled Rules to be output
my %xzone_calls;		# Hash of cross-zone traffic rulesets (eg, xxx_LAN_NET)
my %udc_list;			# Names of User-Defined Chains
my %user_var;			# User Defined Variables

# somewhere to store info for the 'common' rules we have to include in the output
my %spoof_protection;	# Hash of Arrays to store valid networks per interface (see &compile_standard)
my @bogon_protection;	# Array of interfaces to provide bogon protection on
my @portscan_protection;# Array of interfaces to provide portscan protection on
my @xmas_protection;	# Array of interfaces to provide xmas packet protection on

# compile some standard regex patterns
# any variables starting with "qr_" are precompiled regexes
my $qr_mac_address	= qr/(([A-F0-9]{2}[:.-]?){6})/io;
my $qr_hostname		= qr/(([A-Z0-9]|[A-Z0-9][A-Z0-9\-]*[A-Z0-9])\.)*([A-Z]|[A-Z][A-Z0-9\-]*[A-Z0-9])/io;
my $qr_ip_address	= qr/(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/o;
my $qr_ip_cidr		= qr/(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\/([0-9]{1,2}))?/o;
my $qr_if_names		= qr/((eth|ppp|bond|tun|tap|sit|(xen)?br|vif)(\d+|\+)((\.|:)\d+)?|lo)/io;
my $qr_int_name		= qr/\w+/o;
my $qr_first_word	= qr/\A(\w+)/o;
my $qr_define_xzone	= qr/\Adefine\s+rules\s+($qr_int_name)\s+to\s+($qr_int_name)\z/io;
my $qr_define_sub	= qr/\Adefine\s+rules\s+(\w+)\b?\z/io;
my $qr_add_chain	= qr/\Adefine\s+rules\s+(INPUT|FORWARD|OUTPUT)\b?\z/io;
my $qr_def_variable	= qr/\Adefine\s+var(iable)?\s+(\w+)\b?\z/io;
my $qr_tgt_builtins	= qr/\A(accept|drop|reject|log)\b/io;
my $qr_tgt_redirect	= qr/\A(redirect|trap)\b/io;
my $qr_tgt_map		= qr/\Amap\b/io;
my $qr_tgt_common	= qr/\Acommon\b/io;
my $qr_tgt_iptables	= qr/\Aiptables\b/io;
my $qr_tgt_include	= qr/\Ainclude\b(.+)\z/io;
my $qr_end_define	= qr/\Aend\s+define\b?\z/io;
# regex precompilation for keyword matching and extraction
my $qr_kw_protocol	= qr/\bproto(col)? ([\w]+)\b/io;
my $qr_kw_in_int	= qr/\bin ($qr_int_name)\b/io;
my $qr_kw_out_int	= qr/\bout ($qr_int_name)\b/io;
my $qr_kw_src_addr	= qr/\bsource address ($qr_hostname|$qr_ip_cidr)\b/io;
my $qr_kw_dst_addr	= qr/\bdest(ination)? address ($qr_hostname|$qr_ip_cidr)(:(.+))?\b/io;
my $qr_kw_src_ip	= qr/\bsource address ($qr_ip_cidr)(:(.+))?\b/io;
my $qr_kw_dst_ip	= qr/\bdest(ination)? address ($qr_ip_cidr)(:(.+))?\b/io;
my $qr_kw_src_host	= qr/\bsource group (\S+)\b/io;
my $qr_kw_dst_host	= qr/\bdest(ination)? group (\S+)\b/io;
my $qr_kw_src_range	= qr/\bsource range ($qr_ip_address) to ($qr_ip_address)\b/io;
my $qr_kw_dst_range	= qr/\bdest(ination)? range ($qr_ip_address) to ($qr_ip_address)\b/io;
my $qr_kw_sport		= qr/\bsource\s+port\s+(((\d|\w)+:?)+)\b/io;
my $qr_kw_dport		= qr/\b(dest(ination)?)?\s*port (((\d|\w)+:?)+)\b/io;
my $qr_kw_multisport= qr/\bsource\s+ports\s+(((\d|\w)+,?)+)\b/io;
my $qr_kw_multidport= qr/\b(dest(ination)?)?\s*ports\s+(((\d|\w)+,?)+)\b/io;
my $qr_kw_limit		= qr/\blimit (\S+)\s*(burst (\d+))?\b/io;
my $qr_kw_type		= qr/\btype (\S+)\b/io;
my $qr_time24		= qr/([0-1]?\d|2[0-3]):([0-5]\d)(:([0-5]\d))?/o;
my $qr_kw_start		= qr/\bstart ($qr_time24)\b/io;
my $qr_kw_finish	= qr/\bfinish ($qr_time24)\b/io;
my $qr_kw_days		= qr/\bdays? ((((Mon?|Tue?|Wed?|Thu?|Fri?|Sat?|Sun?)\w*),?)+)\b/io;
my $qr_kw_every		= qr/\bevery (\d+)\b/io;
my $qr_kw_offset	= qr/\boffset (\d+)\b/io;
my $qr_kw_state		= qr/\bstate (NEW|ESTABLISHED|RELATED|INVALID|UNTRACKED)\b/io;
my $qr_kw_mac_addr	= qr/\bmac ($qr_mac_address)\b/io;
my $qr_kw_noop		= qr/\b(all)\b/io;
my $qr_call_any		= qr/_ANY(_|\b)/o;
my $qr_call_me		= qr/_ME(_|\b)/o;
my $qr_variable		= qr/\%(\w+)/io;

# Constants
my %BOGON_SOURCES;
$BOGON_SOURCES{'10.0.0.0/8'} = 'Private (RFC 1918)';
$BOGON_SOURCES{'172.16.0.0/12'} = 'Private (RFC 1918)';
$BOGON_SOURCES{'192.168.0.0/16'} = 'Private (RFC 1918)';
$BOGON_SOURCES{'169.254.0.0/16'} = 'Link Local (RFC 3927)';
$BOGON_SOURCES{'127.0.0.0/8'} = 'Loopback (RFC 1122)';
$BOGON_SOURCES{'255.255.255.255'} = 'Broadcast (RFC 919)';
$BOGON_SOURCES{'192.0.2.0/24'} = 'TEST-NET - IANA (RFC 1166)';
$BOGON_SOURCES{'198.51.100.0/24'} = 'TEST-NET-2 - IANA';
$BOGON_SOURCES{'203.0.113.0/24'} = 'TEST-NET-3 - APNIC (RFC 5737)';
$BOGON_SOURCES{'192.0.0.0/24'} = 'IETF Protocol Assignment (RFC 5736)';
$BOGON_SOURCES{'198.18.0.0/15'} = 'Benchmark Testing (RFC 2544)';
$BOGON_SOURCES{'240.0.0.0/4'} = 'Class E Reserved (RFC 1112)';

# Most of these rules gathered from "gotroot.com":
# 	http://www.gotroot.com/Linux+Firewall+Rules
# Included with permission granted via the "GOT ROOT LICENSE":
# 	http://www.gotroot.com/Got+Root+License
my %PORTSCAN_RULES;
$PORTSCAN_RULES{'-p tcp --tcp-flags ALL FIN,URG,PSH'}	= 'PORTSCAN: NMAP FIN/URG/PSH';
$PORTSCAN_RULES{'-p tcp --tcp-flags SYN,RST SYN,RST'}	= 'PORTSCAN: SYN/RST';
$PORTSCAN_RULES{'-p tcp --tcp-flags SYN,FIN SYN,FIN'}	= 'PORTSCAN: SYN/FIN';
$PORTSCAN_RULES{'-p tcp --tcp-flags ALL FIN'}			= 'PORTSCAN: NMAP FIN Stealth';
$PORTSCAN_RULES{'-p tcp --tcp-flags ALL ALL'}			= 'PORTSCAN: ALL/ALL';
$PORTSCAN_RULES{'-p tcp --tcp-flags ALL NONE'}			= 'PORTSCAN: NMAP Null Scan';

# An array of reserved words that can't be used as target names
my @RESERVED_WORDS = qw(
	accept		drop		log
	redirect	trap		map
	common		iptables	include
);

###############################################################################
#### MAIN CODE
###############################################################################

# Handle command line args
&handle_cmd_args;

# read config files
$conf_file = coalesce($conf_file, '/etc/husk/husk.conf');
&read_config_file(fname=>$conf_file);
&load_addrgroups(fname=>sprintf('%s/addr_groups.conf', $conf_dir));
&load_interfaces(fname=>sprintf('%s/interfaces.conf', $conf_dir));

# Start Processing
&init;
&read_rules_file(fname=>sprintf('%s/rules.conf', $conf_dir));
&close_rules;

# Cleanup and Output
&generate_output;

exit 0;

###############################################################################
#### SUBROUTINES
###############################################################################

sub read_rules_file {
	my %args = @_;
	my $fname = $args{'fname'};

	# Validate what was passed
	&bomb((caller(0))[3] . ' called without passing $fname') unless $fname;

	local(*FILE);
	my $closing_tgt;	# Where to JUMP when we close the current chain
	my $in_def_variable;# Boolean if we're "inside" a "define var" block

	# make sure the file exists first
	&bomb(sprintf('Rules file does not exist: %s', $fname))
		unless (-e $fname);

	open FILE, "<$fname" or &bomb("Failed to read $fname");
	my @lines = <FILE>;
	close(FILE);
	$line_cnt = 0;

	# Find and parse all our subroutine chains first
	ParseLines:
	foreach my $line (@lines) {
		chomp($line);
		$line_cnt++;	# Increase the line counter by 1

		# Ignore blank and comment only lines
		$line = &cleanup_line($line);
		next ParseLines unless $line;

		if ($line =~ m/$qr_define_xzone/) {
			# Start of a 'define rules ZONE to ZONE'
			my ($i_name, $o_name) = (uc($1), uc($2));

			# make sure we're not still inside an earlier define rules
			&bomb(sprintf("Line starts before previous 'define' block has ended:\n\t%s", $line))
					if $curr_chain;

			$curr_chain = &new_call_chain(line=>$line, in=>$i_name, out=>$o_name);

			# Work out what to do when this chain ends:
			#	- RETURN for 'ANY' rules
			#	- DROP for all others
			if ($i_name =~ m/ANY/ or $o_name =~ m/ANY/) {
				$closing_tgt = 'RETURN';
			} else {
				$closing_tgt = 'DROP';
			}
		}
		elsif ($line =~ m/$qr_add_chain/) {
			# handle blocks adding to INPUT, OUTPUT and/or FORWARD
			my $chain_name = uc($1);

			# make sure we're not still inside an earlier block
			&bomb(sprintf('"%s" starts before previous define block has ended', $line))
					if $curr_chain;

			$curr_chain = $chain_name;
		}
		elsif ($line =~ m/$qr_define_sub/) {
			# Start of a user-defined chain
			my $udc_name = $1;

			# make sure we're not still inside an earlier block
			&bomb(sprintf("Line starts before previous 'define' block has ended:\n\t%s", $line))
					if $curr_chain;

			# make sure the user isn't trying to use a reserved word
			&bomb(sprintf('Target "%s" is named the same as a reserved word. This is invalid', $udc_name))
				if (grep(m/$udc_name/i, @RESERVED_WORDS));

			$curr_chain = &new_udc_chain(line=>$line, udc_name=>$udc_name);
		}
		elsif ($line =~ m/$qr_tgt_builtins/) {
			# call rule - jump to built-in
			&bomb("Call rule found outside define block on line $line_cnt:\n\t$line")
				unless $curr_chain;
			&compile_call(chain=>$curr_chain, line=>$line);
		}
		elsif ($line =~ m/$qr_def_variable/) {
			my $var_name = $2;
			&bomb("Variable already defined: $var_name")
				if ($user_var{$var_name});
			# Loop through all the next lines until we find 'end define'
			VariableLines:
			for (my $v = $line_cnt; 1; $v++) {
				my $val = $lines[$v];
				chomp($val);

				$val = &cleanup_line($val);

				next VariableLines unless $val;

				last VariableLines if ($val =~ m/$qr_end_define/);

				push(@{$user_var{$var_name}}, $val);
			}
			$in_def_variable = 1;
		}
		elsif ($line =~ m/$qr_tgt_map/) {
			&compile_nat($line);
		}
		elsif ($line =~ m/$qr_tgt_redirect/) {
			# redirect/trap rule
			&compile_interception($line);
		}
		elsif ($line =~ m/$qr_tgt_common/) {
			# 'common' rule
			&compile_common($line);
		}
		elsif ($line =~ s/$qr_tgt_iptables//) {
			# raw iptables command
			my $raw_rule = &trim($line);
			$raw_rule =~ s/%CHAIN%/$curr_chain/;

			my $comment = sprintf('-m comment --comment "husk line %s"', $line_cnt);
			$raw_rule = sprintf('%s %s', $raw_rule, $comment);

			&ipt($raw_rule);
		}
		elsif ($line =~ m/$qr_tgt_include/) {
			# include another rules file
			my $include_file = $1;
			&include_file(fname=>$include_file);
		}
		elsif ($line =~ m/$qr_end_define/) {
			# End of a 'define' block; Clear our state and add default rule

			# make sure we are actually in a define rules block
			&bomb(sprintf('Found "%s" but not inside a "define" block?', $line))
					unless ($curr_chain or $in_def_variable);

			&close_chain(chain=>$curr_chain, closing_tgt=>$closing_tgt)
					if ($curr_chain);

			undef($curr_chain);
			undef($in_def_variable);
			$closing_tgt = '';
		}
		else {
			# Ignore if we're inside a variable declaration
			next ParseLines if ($in_def_variable);

			# Extract the first word of the line
			$line =~ m/$qr_first_word/;
			my $first_word = coalesce($1, '');

			# See if this is a UDC to jump to
			my $udc_chain = sprintf('%s%s', $udc_prefix, $first_word);
			if (defined($udc_list{$udc_chain})) {
				# call rule - jump to udc
				&compile_call(chain=>$curr_chain, line=>$line);
			} else {
				&bomb(sprintf(
					'Unknown command on line %s (perhaps a "define rules" block used before it is defined?):%s %s',
					$line_cnt, "\n\t", $line));
			}
		}
	}

	# finished parsing the rules file; clear the line
	# counter so we don't use it by accident
	undef($line_cnt);
}

sub new_call_chain {
	my %args	= @_;
	my $line	= $args{'line'};
	my $i_name	= uc($args{'in'});
	my $o_name	= uc($args{'out'});
	my $chain	= sprintf("%s_%s_%s", $xzone_prefix, $i_name, $o_name);

	# Validate what we've found
	&bomb(sprintf('Undefined "in" interface on line %s: %s', $line_cnt, $i_name))
		unless ($interface{$i_name} or $i_name =~ m/\AANY\z/);
	&bomb(sprintf('Undefined "out" interface on line %s: %s', $line_cnt, $o_name))
		unless ($interface{$o_name} or $o_name =~ m/\AANY\z/);
	
	# Check if we've seen this call before
	&bomb(sprintf("'%s' defined twice (second on line %s)", $line, $line_cnt))
		if (defined($xzone_calls{$chain}));

	# Is this a bridged interface? We need to use the physdev module if it is
	my ($is_bridge_in, $is_bridge_out);
	$is_bridge_in  = &is_bridged(eth=>$interface{$i_name}) if ($interface{$i_name});
	$is_bridge_out = &is_bridged(eth=>$interface{$o_name}) if ($interface{$o_name});
	
	# Work out if this chain is called from INPUT, OUTPUT or FORWARD
	my %criteria;
	# Set defaults
	$criteria{'chain'}	= 'FORWARD';
	# We ternary test this assignment because sometimes there won't be a
	# corresponding value in %interface (eg, for ANY)
	$criteria{'in'}		= $interface{$i_name} ? sprintf('-i %s', $interface{$i_name}) : '';
	$criteria{'out'}	= $interface{$o_name} ? sprintf('-o %s', $interface{$o_name}) : '';
	# Override defaults if required
	if ($o_name =~ m/\AME\z/) {
		$criteria{'chain'} = 'INPUT';
		$criteria{'out'} = '';	# -o is invalid in INPUT table
	}
	if ($i_name =~ m/\AME\z/) {
		$criteria{'chain'} = 'OUTPUT';
		$criteria{'in'} = '';	# -i is invalid in OUTPUT table
	}
	# Negate the opposite interface on ANY rules
	# so we don't mess with bounce routing
	if ($o_name =~ m/\AANY\z/) {
		$criteria{'out'} = sprintf('! -o %s', $interface{$i_name});
	}
	if ($i_name =~ m/\AANY\z/) {
		$criteria{'in'} = sprintf('! -i %s', $interface{$o_name});
	}
	# Use the physdev module for rules across bridges
	if ($is_bridge_in) {
		$criteria{'module'}	= '-m physdev';
		$criteria{'in'}		= $interface{$i_name} ? sprintf('--physdev-in %s', $interface{$i_name}) : ''
			unless ($i_name =~ m/\AME\z/);
	}
	if ($is_bridge_out) {
		$criteria{'module'}	= '-m physdev';
		$criteria{'out'}	= $interface{$o_name} ? sprintf('--physdev-out %s', $interface{$o_name}) : ''
			unless ($o_name =~ m/\AME\z/);
	}

	# Build the Rule
	&ipt("-N $chain");
	$xzone_calls{$chain} = collapse_spaces(sprintf(
		'-A %s %s %s %s -m state --state NEW -j %s -m comment --comment "husk line %s"',
		$criteria{'chain'},
		$criteria{'module'} ? $criteria{'module'} : '',
		$criteria{'in'},
		$criteria{'out'},
		$chain,
		$line_cnt ? $line_cnt : 'UNKNOWN',
	));

	# Pass the chain name back to where we were called
	return $chain;
}

sub new_udc_chain {
	my %args	= @_;
	my $line	= $args{'line'};
	my $udc_name= $args{'udc_name'};
	my $chain	= sprintf("%s%s", $udc_prefix, $udc_name);

	# Check if we've seen this call before
	&bomb(sprintf("'%s' defined twice (second on line %s)", $line, $line_cnt))
		if ($udc_list{$chain});

	# Store the UDC chain name with the line number for later
	$udc_list{$chain} = $line_cnt;
	
	&ipt("-N $chain");

	return $chain;
}

sub close_chain {
	my %args	= @_;
	my $chain		= $args{'chain'};
	my $closing_tgt	= $args{'closing_tgt'};

	if ($closing_tgt and $closing_tgt =~ m/DROP/) {
		# Cross zone chain with DROP to close with.
		log_and_drop(chain=>$chain);
	} elsif ($closing_tgt) {
		# Cross zone chain with something other than 'DROP'
		# as the closing action.
		&ipt(sprintf('-A %s -j %s', $chain, $closing_tgt));
	} else {
		# This is a UDC; We don't append anything
		;
	}
}

sub close_rules {
	# setup 'common' rules and chains
	if (scalar(@bogon_protection)) {
		# Bogon Protection; per interface
		my $BOGON_CHAIN = 'cmn_BOGON';
		my $BOGON_TABLE = 'mangle';

		# Create a chain for bogon protection
		&ipt(sprintf('-t %s -N %s', $BOGON_TABLE, $BOGON_CHAIN));

		# Populate the new chain with rules
		foreach my $bogon_src (sort(keys %BOGON_SOURCES)) {
			# LOG and DROP bad sources (bogons)
			log_and_drop(
				table=>$BOGON_TABLE,
				chain=>$BOGON_CHAIN,
				prefix=>'BOGON',
				criteria=>sprintf(
					'-s %s -m comment --comment "%s"',
					$bogon_src,
					$BOGON_SOURCES{$bogon_src},
			));
		}
		# End with a default RETURN
		&ipt(sprintf('-t %s -A %s -j RETURN', $BOGON_TABLE, $BOGON_CHAIN));

		# Jump the new chain for packets in the user-specified interfaces
		foreach my $int (@bogon_protection) {
			&ipt(sprintf(
				'-t %s -I PREROUTING -i %s -j %s -m comment --comment "bogon protection for %s"',
				$BOGON_TABLE,
				$interface{$int},
				$BOGON_CHAIN,
				$int,
			));
		}
	}
	
	if (scalar(keys %spoof_protection)) {
		# Antispoof rules; Per interface
		my $SPOOF_CHAIN = 'cmn_SPOOF';
		my $SPOOF_TABLE = 'mangle';

		# Create a chain to log and drop 
		&ipt(sprintf('-t %s -N %s', $SPOOF_TABLE, $SPOOF_CHAIN));

		foreach my $iface (keys %spoof_protection) {
			# RETURN if the packet is sourced from 0.0.0.0 (eg, DHCP Discover)
			&ipt(sprintf('-t %s -A %s -s 0.0.0.0 -p udp --sport 68 --dport 67 -m comment --comment "DHCP Discover bypasses spoof protection" -j RETURN',
					$SPOOF_TABLE,
					$SPOOF_CHAIN,
				));

			# RETURN if the packet is from a known-good source (as specified by user)
			foreach (@{$spoof_protection{$iface}}) {
				my $src = $_;
				&ipt(sprintf(
					'-t %s -A %s -i %s -s %s -m comment --comment "valid source for %s" -j RETURN',
					$SPOOF_TABLE,
					$SPOOF_CHAIN,
					$interface{$iface},
					$src,
					$iface));
			}
			# LOG, then DROP anything else
			log_and_drop(
				table=>$SPOOF_TABLE,
				chain=>$SPOOF_CHAIN,
				prefix=>sprintf('SPOOFED in %s', $iface),
				criteria=>sprintf(
					'-i %s -m comment --comment "bad source in %s"',
					$interface{$iface},
					$iface,
			));
		}
		# End with a default RETURN
		&ipt(sprintf('-t %s -A %s -j RETURN', $SPOOF_TABLE, $SPOOF_CHAIN));

		# Jump the new chain for packets in the user-specified interfaces
		foreach my $int (keys %spoof_protection) {
			&ipt(sprintf('-t %s -I PREROUTING -i %s -j %s -m comment --comment "spoof protection for %s"',
					$SPOOF_TABLE,
					$interface{$int},
					$SPOOF_CHAIN,
					$int,
				));
		}
	}
	
	# xmas Protection
	if (scalar(@xmas_protection)) {
		# Block Xmas Packets
		my $XMAS_CHAIN = 'cmn_XMAS';
		my $XMAS_TABLE = 'mangle';

		&ipt(sprintf('-t %s -N %s', $XMAS_TABLE, $XMAS_CHAIN));
		log_and_drop(
			table=>$XMAS_TABLE,
			chain=>$XMAS_CHAIN,
			prefix=>'XMAS',
			criteria=>'-p tcp --tcp-flags ALL ALL'
		);
		log_and_drop(
			table=>$XMAS_TABLE,
			chain=>$XMAS_CHAIN,
			prefix=>'XMAS',
			criteria=>'-p tcp --tcp-flags ALL NONE'
		);
		# RETURN by default
		&ipt(sprintf('-t %s -A %s -j RETURN', $XMAS_TABLE, $XMAS_CHAIN));
		foreach my $int (@xmas_protection) {
			&ipt(sprintf(
				'-t %s -I PREROUTING -i %s -j %s -m comment --comment "xmas protection for %s"',
				$XMAS_TABLE,
				$interface{$int},
				$XMAS_CHAIN,
				$int,
			));
		}
	}

	if (scalar(@portscan_protection)) {
		# Portscan Protection; per interface
		my $PORTSCAN_CHAIN = 'cmn_PORTSCAN';
		my $PORTSCAN_TABLE = 'mangle';

		# Create a chain for portscan protection
		&ipt(sprintf('-t %s -N %s', $PORTSCAN_TABLE, $PORTSCAN_CHAIN));

		# Populate the new chain with rules
		foreach my $ps_rule (sort(keys %PORTSCAN_RULES)) {
			# LOG and DROP things that look like portscans
			my $scan_desc = $PORTSCAN_RULES{$ps_rule};
			log_and_drop(
				table=>$PORTSCAN_TABLE,
				chain=>$PORTSCAN_CHAIN,
				prefix=>$scan_desc,
				criteria=>sprintf(
					'%s -m comment --comment "%s"',
					$ps_rule,
					$scan_desc,
			));
		}
		# End with a default RETURN
		&ipt(sprintf('-t %s -A %s -j RETURN', $PORTSCAN_TABLE, $PORTSCAN_CHAIN));

		# Jump the new chain for packets in the user-specified interfaces
		foreach my $int (@portscan_protection) {
			&ipt(sprintf(
				'-t %s -I PREROUTING -i %s -j %s -m comment --comment "portscan protection for %s"',
				$PORTSCAN_TABLE,
				$interface{$int},
				$PORTSCAN_CHAIN,
				$int,
			));
		}
	}

	# Create cross-zone chains for anything not defined
	# by the user.
	$line_cnt = 'autogenerated';
	InterfacesFrom:
	foreach my $int_from (keys %interface) {
		InterfacesTo:
		foreach my $int_to (keys %interface) {
			my $new_chain	= sprintf("%s_%s_%s", $xzone_prefix, $int_from, $int_to);
			next InterfacesTo if ($xzone_calls{$new_chain});	# Don't create already existing chains
			next InterfacesTo if ($int_from =~ m/\AME\z/);		# Don't create OUTPUT chains
			next InterfacesTo if ($int_from eq $int_to);		# Don't create bounce chains

			# Create new chain
			my $curr_chain = &new_call_chain(line=>'none', in=>$int_from, out=>$int_to);
			# Close it off
			&close_chain(chain=>$curr_chain, closing_tgt=>'DROP');
		}
	}
	undef($line_cnt);

	# JUMP to cross-zone traffic chains
	# - Jump anything to/from ME first
	my $any_to_me = sprintf('%s_ANY_ME', $xzone_prefix);
	my $me_to_any = sprintf('%s_ME_ANY', $xzone_prefix);
	if (defined($xzone_calls{$any_to_me})) {
		&ipt($xzone_calls{$any_to_me});
		delete $xzone_calls{$any_to_me};
	}
	if (defined($xzone_calls{$me_to_any})) {
		&ipt($xzone_calls{$me_to_any});
		delete $xzone_calls{$me_to_any};
	}
	# We want to jump any chains to/from the
	# special 'ANY' interface before all
	# other 'call' jumps.
    foreach my $xzone_rule (sort(keys %xzone_calls)) {
		if ($xzone_rule =~ m/$qr_call_any/) {
			&ipt($xzone_calls{$xzone_rule});
			delete $xzone_calls{$xzone_rule};
		}
	}
	# Jump whatever else is left
    foreach my $xzone_rule ( sort(keys %xzone_calls )) {
		&ipt($xzone_calls{$xzone_rule});
	}

	# Set policies
	foreach my $chain qw(INPUT FORWARD OUTPUT) {
		&ipt(sprintf('-P %s DROP', $chain));
	}
}

sub generate_output {
	unless ($script_output) {
		# Just dump the rules to stdout as plain iptables
		foreach (@output_rules) {
			printf("%s %s\n", $iptables, $_);
		}
	} else {
		# iptables-restore script
		my ($table, %split_rules, %chain_names, %policy);
		foreach (@output_rules) {
			# 1. split the output rules array into an array
			#	for each table (filter, nat, mangle and raw)
			#	also itemize each chain name into a hash per
			#	table.
			my $r = $_;
			if ($r =~ m/(-t (filter|nat|mangle|raw))? ?(-[AI].*)\z/g) {
				my $t = 'filter';   # Default; could be overwritten on next line
				$t = $2 if $2;
				push(@{$split_rules{$t}}, $3);
			} elsif ($r =~ m/-P (INPUT|FORWARD|OUTPUT) (DROP|ACCEPT)\z/g) {
				# Convert Policies
				$policy{$1} = $2;
			} elsif ($r =~ m/(-t (filter|nat|mangle|raw) )?-N (\S+)\z/g) {
				$table = coalesce($2, 'filter');
				push(@{$chain_names{$table}}, $3);
			} elsif ($r =~ m/(-t (filter|nat|mangle|raw) )?(-[XFZ] (\S+)( \S+))?\z/g) {
				my $c = $1;
			} else {
				print "WTF ERROR; $r\n";
			}
		}
		printf("# Generated by husk v%s %s\n", $VERSION, &timestamp);
		# filter table
		print "*filter\n";
		foreach my $chain qw(INPUT FORWARD OUTPUT) {
			$policy{$chain} = 'DROP' unless $policy{$chain}; 
			print ":$chain $policy{$chain} [0:0]\n";
		}
		foreach (@{$chain_names{'filter'}}) {
			my $udc = $_;
			print ":$udc - [0:0]\n";
		}
		print "COMMIT\n";
		foreach my $rule (@{$split_rules{'filter'}}) {
			print "$rule\n";
		}
		# nat table
		print "*nat\n";
		foreach my $chain qw(PREROUTING POSTROUTING OUTPUT TEST) {
			$policy{$chain} = 'DROP' unless $policy{$chain}; 
			print ":$chain $policy{$chain} [0:0]\n";
		}
		foreach (@{$chain_names{'nat'}}) {
			my $udc = $_;
			print ":$udc - [0:0]\n";
		}
		print "COMMIT\n";
		foreach my $rule (@{$split_rules{'nat'}}) {
			print "$rule\n";
		}
		# mangle table
		print "*mangle\n";
		foreach my $chain qw(INPUT FORWARD OUTPUT PREROUTING POSTROUTING) {
			$policy{$chain} = 'DROP' unless $policy{$chain}; 
			print ":$chain $policy{$chain} [0:0]\n";
		}
		foreach (@{$chain_names{'mangle'}}) {
			my $udc = $_;
			print ":$udc - [0:0]\n";
		}
		print "COMMIT\n";
		foreach my $rule (@{$split_rules{'mangle'}}) {
			print "$rule\n";
		}
		# raw table
		print "*raw\n";
		foreach my $chain qw(PREROUTING OUTPUT) {
			$policy{$chain} = 'DROP' unless $policy{$chain}; 
			print ":$chain $policy{$chain} [0:0]\n";
		}
		foreach (@{$chain_names{'raw'}}) {
			my $udc = $_;
			print ":$udc - [0:0]\n";
		}
		print "COMMIT\n";
		foreach my $rule (@{$split_rules{'raw'}}) {
			print "$rule\n";
		}
	}
}

sub log_and_drop {
	my %args = @_;
	my $chain		= $args{'chain'};
	my $table		= $args{'table'} ? sprintf('-t %s', $args{'table'}) : '';
	my $log_prefix	= coalesce($args{'prefix'}, $chain);
	my $criteria	= $args{'criteria'} ? $args{'criteria'} : '';

	# Validate what was passed
	&bomb((caller(0))[3] . ' called without passing $chain') unless $chain;

	# LOG the packet
	&ipt(&collapse_spaces(sprintf('%s -A %s %s -m limit --limit 4/minute --limit-burst 3 -j LOG --log-prefix="[%s] "',
			$table, $chain, $criteria, $log_prefix,
		)));
	# DROP the packet
	&ipt(&collapse_spaces(sprintf('%s -A %s %s -j DROP',
			$table, $chain, $criteria,
		)));

	return;
}

###############################################################################
#### COMPILATION SUBROUTINES
###############################################################################

sub compile_call {
	# Compiles a filter rule into an iptables rule.
	my %args	= @_;
	my $chain	= coalesce($args{'chain'}, '');
	my $rule	= coalesce($args{'line'}, '');
	
	# Keep the rule intact in this var for user display if reqd for errors
	my $complete_rule = $rule;

	# Validate input
	&bomb("Invalid input to &compile_call") unless $chain;
	&bomb("Invalid input to &compile_call") unless $rule;

	# See if any variables are used in this rule. If so, call ourself
	# recursively for each element in the var
	if ($rule =~ m/\s$qr_variable\b/) {
		my $var_name = $1;
		foreach (@{$user_var{$var_name}}) {
			my $var_value = $_;
			my $recurse_rule = $rule;
			$recurse_rule =~ s/\s%$var_name\b/ $var_value /;
			&compile_call(chain=>$chain, line=>$recurse_rule);
		}
		# No need to continue from here; Return early.
		return 1;
	}
	
	# Hash to store all the individual parts of this rule
	my %criteria;

	# Extract the individual parts of the rule into our hash
	if ($rule =~ s/$qr_tgt_builtins//s) {
		# iptables inbuilt targets and UC them.
		$criteria{'target'} = uc($1)
	} elsif ($rule =~ s/$qr_first_word//) {;
		# assume it's a user defined target (chain)
		$criteria{'target'} = sprintf('%s%s', $udc_prefix, $1);
	}
	if ($rule =~ s/$qr_kw_protocol//s)
		{$criteria{'proto'} = lc($2)};
	if ($rule =~ s/$qr_kw_in_int//s)
		{$criteria{'i_name'} = $interface{uc($1)}};
	if ($rule =~ s/$qr_kw_out_int//s)
		{$criteria{'o_name'} = $interface{uc($1)}};
	if ($rule =~ s/$qr_kw_src_addr//s)
		{$criteria{'src'} = lc($1)};
	if ($rule =~ s/$qr_kw_dst_addr//s)
		{$criteria{'dst'} = lc($2)};
	if ($rule =~ s/$qr_kw_src_host//s)
		{$criteria{'sgroup'} = $1};
	if ($rule =~ s/$qr_kw_dst_host//s)
		{$criteria{'dgroup'} = $2};
	if ($rule =~ s/$qr_kw_src_range//s)
		{$criteria{'srcrange'} = "$1-$2"};
	if ($rule =~ s/$qr_kw_dst_range//s)
		{$criteria{'dstrange'} = "$2-$3"};
	if ($rule =~ s/$qr_kw_sport//s) {
		my $port = lc($1);
		$criteria{'spt'} = $port;
	}
	if ($rule =~ s/$qr_kw_dport//s) {
		my $port = lc($3);
		$criteria{'dpt'} = $port;
	}
	if ($rule =~ s/$qr_kw_multisport//s) {
		my $ports = lc($1);
		$criteria{'spts'} = $ports;
	}
	if ($rule =~ s/$qr_kw_multidport//s) {
		my $ports = lc($3);
		$criteria{'dpts'} = $ports;
	}
	if ($rule =~ s/$qr_kw_start//s)
		{$criteria{'time_start'} = $1};
	if ($rule =~ s/$qr_kw_finish//s)
		{$criteria{'time_finish'} = $1};
	if ($rule =~ s/$qr_kw_days//s)
		{my @days = split(/,/, $1);
		 foreach my $day (@days) {
			 $criteria{'time_days'} .= substr($day, 0, 2) . ',';
		 }
		 # Strip the trailing comma
		 $criteria{'time_days'} =~ s/,\z//;
	};
	if ($rule =~ s/$qr_kw_every//s)
		{$criteria{'statistics_every'} = $1};
	if ($rule =~ s/$qr_kw_offset//s)
		{$criteria{'statistics_offset'} = $1};
	if ($rule =~ s/$qr_kw_state//s)
		{$criteria{'state'} = uc($1)};
	if ($rule =~ s/$qr_kw_limit//s)
		{$criteria{'limit'} = lc($1);
		 $criteria{'burst'} = $3}
	if ($rule =~ s/$qr_kw_type//s)
		{$criteria{'icmp_type'} = lc($1); delete $criteria{'proto'};}
	if ($rule =~ s/$qr_kw_mac_addr//s)
		{$criteria{'mac'} = uc($1)};
	if ($rule =~ s/$qr_kw_noop//s)
		# No-op for Keywords: 'all' 'count'
		{;}

	# aggregate criteria from the same module to one module
	# reference in the output rule
	$criteria{'time'} = collapse_spaces(sprintf('%s %s %s',
			defined($criteria{'time_start'})		?
				"--timestart $criteria{'time_start'}"
				: '',
			defined($criteria{'time_finish'})		?
				"--timestop $criteria{'time_finish'}"
				: '',
			defined($criteria{'time_days'})		?
				"--weekdays $criteria{'time_days'}"
				: '',
			));
	$criteria{'statistic'} = collapse_spaces(sprintf('%s %s ',
			defined($criteria{'statistics_every'})		?
				"-m statistic --mode nth --every $criteria{'statistics_every'}"
				: '',
			defined($criteria{'statistics_offset'})		?
				"--packet $criteria{'statistics_offset'}"
				: '',
			));

	# make sure we've understood everything on the line, otherwise BARF!
	&unknown_keyword(rule=>$rule, complete_rule=>$complete_rule)
		if (&trim($rule));

	if ($criteria{'sgroup'} or $criteria{'dgroup'}) {
		# recurse ourself for each 'source group' or 'destination group'
		my $addrgrp;
		$addrgrp = $criteria{'sgroup'} if $criteria{'sgroup'};
		$addrgrp = $criteria{'dgroup'} if $criteria{'dgroup'};
		&bomb(sprintf('Unknown address group: %s', $addrgrp))
			unless $addr_group{$addrgrp};

		#my @ag_addresses = split(/\n/, $addr_group{$addrgrp}{'hosts'});
		my @ag_addresses = @{$addr_group{$addrgrp}{'hosts'}};
		foreach (@ag_addresses) {
			my $addr = $_;
			my $recurse_rule = $complete_rule;
			$recurse_rule =~ s/\bgroup $addrgrp\b/address $addr/gi;
			&compile_call(chain=>$chain, line=>$recurse_rule);
		}
	} else {
		# otherwise, build the rule into an iptables command
		&ipt(collapse_spaces(
			sprintf('-A %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s -m comment --comment "husk line %s"',
			$chain,
			defined($criteria{'target'})	?
				"-j $criteria{'target'}"	: '',
			defined($criteria{'proto'})		?
				"-p $criteria{'proto'}"		: '',
			defined($criteria{'src'})		?
				"-s $criteria{'src'}"		: '',
			defined($criteria{'dst'})		?
				"-d $criteria{'dst'}"		: '',
			defined($criteria{'i_name'})	?
				"-i $criteria{'i_name'}"	: '',
			defined($criteria{'o_name'})	?
				"-o $criteria{'o_name'}"	: '',
			defined($criteria{'spt'})		?
				"--sport $criteria{'spt'}"	: '',
			defined($criteria{'spts'})		?
				"-m multiport --sports $criteria{'spts'}"
				: '',
			defined($criteria{'dpt'})		?
				"--dport $criteria{'dpt'}"	: '',
			defined($criteria{'dpts'})		?
				"-m multiport --dports $criteria{'dpts'}"
				: '',
			defined($criteria{'icmp_type'})	?
				"-p icmp --icmp-type $criteria{'icmp_type'}"
				: '',
			defined($criteria{'limit'})		?
				"-m limit --limit $criteria{'limit'}"
				: '',
			defined($criteria{'burst'})		?
				"--limit-burst $criteria{'burst'}"
				: '',
			$criteria{'time'}		?
				"-m time $criteria{'time'}"
				: '',
			$criteria{'statistic'}	?
				"-m statistic $criteria{'statistic'}"
				: '',
			defined($criteria{'state'})		?
				"-m state --state $criteria{'state'}"
				: '',
			defined($criteria{'srcrange'})	?
				"-m iprange --src-range $criteria{'srcrange'}"
				: '',
			defined($criteria{'dstrange'})	?
				"-m iprange --dst-range $criteria{'dstrange'}"
				: '',
			defined($criteria{'mac'})		?
				"-m mac --mac-source $criteria{'mac'}"
				: '',
			$line_cnt))
		);
	}
}

sub compile_nat {
	# Compiles a 'map' rule into an iptables DNAT and SNAT rule.
	my($rule) = @_;
	my $complete_rule = $rule;
	
	# strip out the leading 'common' keyword
	$rule =~ s/$qr_tgt_map//s;
	$rule =~ &cleanup_line($rule);

	# Hash to store all the individual parts of this rule
	my %criteria;

	if ($rule =~ s/$qr_kw_in_int//s)
		{$criteria{'in'}	= uc($1)}
	if ($rule =~ s/$qr_kw_protocol//s)
		{$criteria{'proto'}	= lc($2)}
	if ($rule =~ s/$qr_kw_dst_ip//s)
		{$criteria{'inet_ext'}	= lc($2)}
	if ($rule =~ s/$qr_kw_sport//s) {
		my $port = lc($1);
		$criteria{'sport_ext'} = $port;
	}
	if ($rule =~ s/$qr_kw_dport//s) {
		my $port = lc($3);
		$criteria{'dport_ext'} = $port;
	}
	if ($rule =~ s/$qr_kw_multisport//s) {
		my $ports = lc($1);
		$criteria{'sports_ext'} = $ports;
	}
	if ($rule =~ s/$qr_kw_multidport//s) {
		my $ports = lc($3);
		$criteria{'dports_ext'} = $ports;
	}
	if ($rule =~ s/to ([^: ]+)(:([0-9]+))?\b//si)
		{$criteria{'inet_int'}	= $1}
	if ($rule =~ s/to ([^: ]+)(:([0-9]+))?\b//si)
		{$criteria{'port_int'}	= $3}

	# make sure we've understood everything on the line, otherwise BARF!
	&unknown_keyword(rule=>$rule, complete_rule=>$complete_rule)
		if (&trim($rule));

	# DNAT with the criteria defined
	&ipt(&collapse_spaces(sprintf(
			'-t nat -A PREROUTING %s %s %s %s %s %s %s -j DNAT %s%s',
			$criteria{'in'}			? "-i $interface{$criteria{'in'}}"					: '',
			$criteria{'proto'}		? "-p $criteria{'proto'}"							: '',
			$criteria{'inet_ext'}	? "-d $criteria{'inet_ext'}"						: '',
			$criteria{'sport_ext'}	? "--sport $criteria{'sport_ext'}"					: '',
			$criteria{'dport_ext'}	? "--dport $criteria{'dport_ext'}"					: '',
			$criteria{'sports_ext'}	? "-m multiport --sports $criteria{'sports_ext'}"	: '',
			$criteria{'dports_ext'}	? "-m multiport --dports $criteria{'dports_ext'}"	: '',
			$criteria{'inet_int'}	? "--to $criteria{'inet_int'}"						: '',
			$criteria{'port_int'}	? ":$criteria{'port_int'}"							: '',
		)));
	# SNAT with the criteria inversed (ie, dest become source and vice-versa)
#	&ipt(&collapse_spaces(sprintf(
#			'-t nat -A POSTROUTING %s %s %s %s %s %s %s -j SNAT %s',
#			$criteria{'in'}			? "-o $interface{$criteria{'in'}}"					: '',
#			$criteria{'proto'}		? "-p $criteria{'proto'}"							: '',
#			$criteria{'inet_int'}	? "-s $criteria{'inet_int'}"						: '',
#			$criteria{'sport_ext'}	? "--dport $criteria{'sport_ext'}"					: '',
#			$criteria{'dport_ext'}	? "--sport $criteria{'dport_ext'}"					: '',
#			$criteria{'sports_ext'}	? "-m multiport --dports $criteria{'sports_ext'}"	: '',
#			$criteria{'dports_ext'}	? "-m multiport --sports $criteria{'dports_ext'}"	: '',
#			$criteria{'inet_ext'}	? "--to $criteria{'inet_ext'}"						: '',
#		)));
}

sub compile_interception {
	# Compiles a 'redirect' or 'intercept' rule into an iptables REDIRECT rule.
	my($rule) = @_;
	my $complete_rule = $rule;
	
	# strip out the leading 'common' keyword
	$rule =~ s/$qr_tgt_redirect//s;
	$rule =~ &cleanup_line($rule);

	# Hash to store all the individual parts of this rule
	my %criteria;

	if ($rule =~ s/$qr_kw_in_int//s)
		{$criteria{'in'}	= uc($1)}
	if ($rule =~ s/$qr_kw_protocol//s)
		{$criteria{'proto'}	= lc($2)}
	if ($rule =~ s/$qr_kw_dst_addr//s)
		{$criteria{'inet_ext'}	= lc($2)}
	if ($rule =~ s/$qr_kw_sport//s) {
		my $port = lc($1);
		$criteria{'spt'} = $port;
	}
	if ($rule =~ s/$qr_kw_dport//s) {
		my $port = lc($3);
		$criteria{'dpt'} = $port;
	}
	if ($rule =~ s/$qr_kw_multisport//s) {
		my $ports = lc($1);
		$criteria{'spts'} = $ports;
	}
	if ($rule =~ s/$qr_kw_multidport//s) {
		my $ports = lc($3);
		$criteria{'dpts'} = $ports;
	}
	if ($rule =~ s/to ([0-9]+)\b//si)
		{$criteria{'port_redir'} = $1}

	# make sure we've understood everything on the line, otherwise BARF!
	&unknown_keyword($rule, $complete_rule) if (&trim($rule));

	&ipt(&collapse_spaces(sprintf(
			'-t nat -A PREROUTING %s %s %s %s %s -j REDIRECT %s',
			$criteria{'in'}			? "-i $interface{$criteria{'in'}}"	: '',
			$criteria{'proto'}	  	? "-p $criteria{'proto'}"			: '',
			$criteria{'inet_ext'}   ? "-d $criteria{'inet_ext'}"		: '',
			$criteria{'spt'}		? "--sport $criteria{'spt'}"		: '',
			$criteria{'dpt'}		? "--dport $criteria{'dpt'}"		: '',
			$criteria{'spts'}		? "-m multiport --sports $criteria{'spts'}"		: '',
			$criteria{'dpts'}		? "-m multiport --dports $criteria{'dpts'}"		: '',
			$criteria{'port_redir'} ? "--to $criteria{'port_redir'}"	: '',
		)));
}

sub compile_common {
	# Compiles a 'common' rule into an iptables rule.
	my ($line) = @_;

	my $qr_OPTS			= qr/\b?(.+)?/o;
	my $qr_CMN_NAT		= qr/\Anat ($qr_int_name)/io;	# No \z on here because there's extra processing done in the if block
	my $qr_CMN_LOOPBACK	= qr/\Aloopback\z/io;
	my $qr_CMN_SYN		= qr/\Asyn\b?\z/io;
	my $qr_CMN_SPOOF	= qr/\Aspoof ($qr_int_name)$qr_OPTS\z/io;
	my $qr_CMN_BOGON	= qr/\Abogon ($qr_int_name)$qr_OPTS\z/io;	# TODO: Use options for 'nolog'
	my $qr_CMN_PORTSCAN	= qr/\Aportscan ($qr_int_name)\z/io;
	my $qr_CMN_XMAS		= qr/\Axmas ($qr_int_name)\z/io;

	# strip out the leading 'common' keyword
	$line =~ s/$qr_tgt_common//s;
	$line = &cleanup_line($line);

	if ($line =~ m/$qr_CMN_NAT/) {
		# SNAT traffic out a given interface
		my $snat_oeth = uc($1);
		my $snat_chain = sprintf('snat_%s', $snat_oeth);

		# Validate
		&bomb(sprintf('Invalid interface specified for SNAT: %s', $snat_oeth))
			unless ($interface{$snat_oeth});

		# Create a SNAT chain for this interface
		&ipt(sprintf('-t nat -N %s', $snat_chain));

		# Work out if we're SNAT'ing or MASQUERADING
		my $snat_ip;
		if ($line =~ s/\bto\s+($qr_ip_address)\b//si) {
			$snat_ip = $1;
		}
		
		# Add SNAT rules to the SNAT chain
		if ($snat_ip) {
			# User specified a SNAT address
			&ipt(&collapse_spaces(sprintf(
					'-t nat -A %s -j SNAT --to %s -m comment --comment "husk line %s"',
					$snat_chain,
					$snat_ip,
					$line_cnt,
			)));
		} else {
			# Default to MASQUERADE
			# This allows the 'src' argument in the kernel to
			# be used to specify the source address used for
			# outgoing packets. Useful in configurations where
			# HA is used, and there is a 'src' argument to tell
			# the kernel to prefer the Virtual Address as the
			# source.
			&ipt(&collapse_spaces(sprintf(
					'-t nat -A %s -j MASQUERADE -m comment --comment "husk line %s"',
					$snat_chain,
					$line_cnt,
			)));
		}
		
		# Call the snat chain from POSTROUTING for private addresses
		foreach my $rfc1918 qw(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16) {
			&ipt(sprintf('-t nat -A POSTROUTING -o %s -s %s -j %s -m comment --comment "husk line %s"',
					$interface{$snat_oeth},
					$rfc1918,
					$snat_chain,
					$line_cnt,
			));
		}
	}
	elsif ($line =~ m/$qr_CMN_LOOPBACK/) {
		# loopback accept
		&ipt(sprintf('-A INPUT -i lo -j ACCEPT -m comment --comment "husk line %s"', $line_cnt));
		&ipt(sprintf('-A INPUT ! -i lo -s 127.0.0.0/8 -j DROP -m comment --comment "husk line %s"', $line_cnt));
		&ipt(sprintf('-A OUTPUT -o lo -j ACCEPT -m comment --comment "husk line %s"', $line_cnt));
	}
	elsif ($line =~ m/$qr_CMN_SYN/) {
		# syn protections
		my $SYN_PROT_TABLE = 'mangle';
		my $SYN_PROT_CHAIN = 'SYN_PROT';

		# Create the chain
		&ipt(sprintf('-t %s -N %s', $SYN_PROT_TABLE, $SYN_PROT_CHAIN));
		# Log first
		log_and_drop(
			table=>$SYN_PROT_TABLE,
			chain=>$SYN_PROT_CHAIN,
			prefix=>'NEW_NO_SYN',
			criteria=>'-p tcp ! --syn'
		);
		# Call the SYN protection chain from PREROUTING for packets in a NEW connection
		&ipt(sprintf('-t %s -A PREROUTING -m state --state NEW -j %s -m comment --comment "husk line %s"',
				$SYN_PROT_TABLE,
				$SYN_PROT_CHAIN,
				$line_cnt,
			));
	}
	elsif ($line =~ m/$qr_CMN_SPOOF/) {
		# antispoof rule
		my $iface = $1;
		my $src = $2;
		
		# Validate
		&bomb(sprintf('Invalid interface specified for Spoof Protection: %s', $iface))
			unless ($interface{$iface});

		# antispoof configuration is stored in a hash of arrays
		# then processed into iptables commands in &close_rules
		# Example:
		#   {DMZ} => ( 1.2.3.0/24 )
		#   {LAN} => ( 10.0.0.0/24 10.0.1.0/24 )
		push(@{$spoof_protection{$iface}}, $src);
	}
	elsif ($line =~ m/$qr_CMN_BOGON/) {
		# antibogon rule
		# The term "bogon" stems from hacker jargon, where it is defined
		# as the quantum of "bogosity", or the property of being bogus.
		my $iface = $1;

		# Validate
		&bomb(sprintf('Invalid interface specified for Bogon Protection: %s', $iface))
			unless ($interface{$iface});

		push(@bogon_protection, $iface);
	}
	elsif ($line =~ m/$qr_CMN_PORTSCAN/) {
		# portscan protection
		my $iface = $1;

		# Validate
		&bomb(sprintf('Invalid interface specified for Portscan Protection: %s', $iface))
			unless ($interface{$iface});

		push(@portscan_protection, $iface);
	}
	elsif ($line =~ m/$qr_CMN_XMAS/) {
		# xmas packet rule
		my $iface = $1;
		
		# Validate
		&bomb(sprintf('Invalid interface specified for Xmas Protection: %s', $iface))
			unless ($interface{$iface});

		push(@xmas_protection, $iface);
	}
}

###############################################################################
#### INITIALIZATION SUBROUTINES
###############################################################################

sub read_config_file {
	my %args = @_;
	my $fname = $args{'fname'};

	# Validate what was passed
	&bomb((caller(0))[3] . ' called without passing $fname') unless $fname;

	# make sure the file exists first
	&bomb(sprintf('Configuration file not found: %s', $fname))
		unless (-e $fname);

	my $cfg = new Config::Simple($fname);
	my %config = $cfg->vars();
	$conf_dir			= coalesce($config{'default.conf_dir'}, '/etc/husk');
	$iptables			= coalesce($config{'default.iptables'}, `which iptables`);
	$iptables_restore	= coalesce($config{'default.iptables-restore'}, `which iptables-restore`);
	$udc_prefix			= coalesce($config{'default.udc_prefix'}, 'tgt_');
	chomp($conf_dir);
	chomp($iptables);
	chomp($iptables_restore);
	chomp($udc_prefix);

	# validate config
	{
		# strip trailing slash from conf_dir
		$conf_dir =~ s/\/*\z//g;

		# check everything actually exists
		&bomb(sprintf('Configuration dir not found: %s', $conf_dir))
			unless (-e $conf_dir);
		&bomb(sprintf('Could not find iptables binary: %s', $iptables))
			unless (-e $iptables);
		&bomb(sprintf('Could not find iptables-restore binary: %s', $iptables_restore))
			unless (-e $iptables_restore);
	}
}

sub load_addrgroups {
	# Access the array of hosts by:
	#   foreach (@{$addr_group{'rfc1918'}{'hosts'}}) {
	my %args = @_;
	my $fname = $args{'fname'};

	# Validate what was passed
	&bomb((caller(0))[3] . ' called without passing $fname') unless $fname;

	if ( -e $fname) {
		tie %addr_group, 'Config::IniFiles', ( -file => $fname );
	}
}

sub load_interfaces {
	# Loads interfaces.conf file. This file maps
	# symbolic names to actual devices.
	# Example:
	#   LAN => eth1
	#   DMZ => eth2
	#   NET => ppp0
	my %args = @_;
	my $fname = $args{'fname'};

	my $qr_NAME_ZONE = qr/\Azone\s+(\w+)\s+is\s+($qr_if_names)\b?\z/io;

	# Validate what was passed
	&bomb((caller(0))[3] . ' called without passing fname') unless $fname;

	local(*FILE);
	open FILE, "$fname" or &bomb("Failed to read $fname");
	InterfacesLoop:
	while (<FILE>) {
		my($int, $name);
		my $line = $_;
		chomp($line);

		# strip comments
		$line = &cleanup_line($line);

		# ignore if the line is blank
		next InterfacesLoop unless $line;

		if ($line =~ m/$qr_NAME_ZONE/) {
			$name	= uc($1);
			$int	= $2;
		} else {
			&bomb(sprintf('Bad config in "%s": %s', $fname, $line))
		}

        # make sure it's not already defined
        $fname = &basename($fname);
        &bomb(sprintf('Zone "%s" defined twice in "%s"', $name, $fname))
            if ($interface{$name});
        for my $i ( keys %interface ) {
			&bomb(sprintf('Interface "%s" named twice in "%s"', $int, $fname))
				if ($interface{$i} =~ m/\A$int\z/);
        }

		# add to the hash
		$interface{$name} = $int;
	}

	# Make sure we have a ME = lo definition
	&bomb(sprintf('Interface "lo" must be defined as "ME" in "%s"', $fname))
		unless ($interface{'ME'} =~ m/\Alo\z/);
}

###############################################################################
#### HELPER SUBROUTINES
###############################################################################

sub unknown_keyword {
	my %args = @_;
	my $rule = $args{'rule'};
	my $complete_rule = $args{'complete_rule'};

	# Validate what was passed
	&bomb((caller(0))[3] . ' called without passing $rule')
		unless $rule;
	&bomb((caller(0))[3] . ' called without passing $complete_rule')
		unless $complete_rule;

	my $unknown_keyword;
	$rule =~ m/^\s*\b(\S+)+\b/; $unknown_keyword = $1;
	$complete_rule =~ m/\b$unknown_keyword\b/; my $pos = length($`) + 1;
	&bomb(sprintf(
		"Unknown keyword(s) found: %s\n\t%s\n\t%${pos}s-- HERE",
		&trim($rule),
		$complete_rule,
		'^'));
}

sub handle_cmd_args {
	GetOptions(
		"script"	=> \$script_output,
		"conf=s"	=> \$conf_file,
	) or &usage();
}

sub init {
	# wipe everything so we know we are starting fresh
	foreach my $table qw(filter nat mangle raw) {
		&ipt("-t $table -F");
		&ipt("-t $table -X");
		&ipt("-t $table -Z");
	}

	# reset policies to ACCEPT
	foreach my $chain qw(INPUT OUTPUT FORWARD) {
		&ipt("-P $chain ACCEPT");
	}

	# add standard rules
	foreach my $chain qw(INPUT FORWARD OUTPUT) {
		&ipt(sprintf('-A %s -m state --state ESTABLISHED -j ACCEPT', $chain));
		&ipt(sprintf('-A %s -m state --state RELATED -j ACCEPT', $chain));
	}
}

sub include_file {
	my %args = @_;
	my $fname = $args{'fname'};

	# Validate what was passed
	&bomb((caller(0))[3] . ' called without passing $fname') unless $fname;

	$fname = &trim($fname);

	# prepend $conf_dir if we're given a relative filename
	$fname = "$conf_dir/$fname" unless ($fname =~ m/^\//g);

	# Store our current line counter;
	my $orig_line_count = $line_cnt;

	# Parse the include file;
	&read_rules_file(fname=>$fname);

	# Restore our line counter
	$line_cnt = $orig_line_count;
}

sub ipt {
	my ($line) = @_;
	push(@output_rules, $line);
}

sub is_bridged {
	# See if an interface belongs to a bridge
	my %args = @_;
	my $eth = $args{'eth'};

	# Validate what was passed
	&bomb((caller(0))[3] . ' called without passing $eth') unless $eth;

	# If the interface has a '+' then it's a wildcard so we
	# need to take it out and let the regex below handle it.
	$eth =~ s/\+\z//;

	my $bridges = `brctl show 2> /dev/null`;
	return 1 if ($bridges =~ m/\b$eth$/m);
	return 1 if ($bridges =~ m/\b$eth((\d|\.|:)+)?$/m);
	return;
}

sub bomb {
	# Error handling; Yay!
	my ($msg) = @_; $msg = 'Unspecified Error' unless $msg;
	if ($line_cnt) {
		printf("BOMBS AWAY (Line %s): %s\n", $line_cnt, $msg);
	} else {
		printf("BOMBS AWAY: %s\n", $msg);
	}
	exit 1;
}

sub dbg {
	# Debug Helper
	my ($msg) = @_; $msg = 'Unspecified Error' unless $msg;
	print "DEBUG: $msg\n";
}

sub basename {
	my $s = $1;
	$s =~ s/\A.*\///;
	return $s;
}

sub collapse_spaces {
	# Collapse multiple spaces into a single
	# space in the supplied string.
	my ($string) = @_;
	return $string = join(' ', split(' ', $string));
}

sub trim {
	my $string = shift;
	$string =~ s/\A\s+//;
	$string =~ s/\s+\z//;
	return $string;
}

sub cleanup_line {
	my ($line) = @_;
	# Strip Comments and Trim
	$line =~ s/\s*#.*\z//;
	$line = &trim($line);
}

sub coalesce {
	# Perl 5.10 supports a proper coalesce operator (//) but
	# it isn't widely packaged and distributed yet (well, I've
	# only checked CentOS, but that's where I use husk, so until
	# Perl 5.10 is more widely used, we'll do our own
	# coalescing here.
	my @args = @_;
	foreach my $val (@args) {
		return $val if defined($val);
	}
	return;
}

sub timestamp {
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)=localtime(time);
	return sprintf(
		"%4d-%02d-%02d %02d:%02d:%02d", 
		$year+1900, $mon+1, $mday, $hour, $min, $sec
	);
}

sub usage {
	print "Usage: husk [options]\n";
	print "Options:\n";
	printf "   %-25s %-50s\n", '--script', 'output an iptables script instead of iptables commands';
	printf "   %-25s %-50s\n", '--conf=/path/to/husk.conf', 'specify an alternate config file';
	exit 1;
}

