#!/usr/bin/perl

package IPTables::Rule;
use strict;
use warnings;

my $qr_number		= qr/[0-9]+/o;
my $qr_alphanum		= qr/[0-9a-z]+/oi;
my $qr_alpha		= qr/[a-z]+/oi;
my $qr_mac_address	= qr/(([A-F0-9]{2}[:.-]?){6})/io;
my $qr_hostname		= qr/(([A-Z0-9]|[A-Z0-9][A-Z0-9\-]*[A-Z0-9])\.)*([A-Z]|[A-Z][A-Z0-9\-]*[A-Z0-9])/io;
my $qr_ip4_address	= qr/(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/o;
my $qr_ip4_cidr		= qr/(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\/([0-9]{1,2}))?/o;
my $qr_ip6_address	= qr/${\&make_ipv6_regex()}/io;
my $qr_ip6_cidr		= qr/${\&make_ipv6_regex()}(\/[0-9]{1,3})?/io;
my $qr_eth_name		= qr/\w{2,5}$qr_number/o;
my $qr_int_name		= qr/\w+/o;
my $qr_protocols	= qr/(tcp|udp|udplite|icmp|icmpv6|esp|ah|sctp|all)/io;
my $qr_tcp_states	= qr/(NEW|ESTABLISHED|RELATED|INVALID|UNTRACKED)/io;
my $qr_port			= $qr_alphanum;
my $qr_port_list	= qr/($qr_alphanum+,)+$qr_alphanum+/oi;
my $qr_port_range	= qr/($qr_alphanum+:)+$qr_alphanum+/oi;
my $qr_weekdays		= qr/((((Mon?|Tue?|Wed?|Thu?|Fri?|Sat?|Sun?)\w*),?)+)/io;
my $qr_time24		= qr/(2[0-3]|[01]?[0-9]):([0-5]?[0-9]):([0-5]?[0-9])/o;
my $qr_iso8601		= qr/(\d{4})\D?(0[1-9]|1[0-2])\D?([12]\d|0[1-9]|3[01])(\D?([01]\d|2[0-3])\D?([0-5]\d)\D?([0-5]\d)?\D?(\d{3})?)?/o;
my $qr_builtins		= qr/(ACCEPT|DROP|REJECT|LOG|QUEUE|NFQUEUE|RETURN)/io;
my $qr_tables		= qr/(filter|nat|mangle|raw)/io;
my %qr_chains		= (
	filter	=> qr/(FORWARD|(IN|OUT)PUT)/io,
	nat		=> qr/(OUTPUT|(PRE|POST)ROUTING)/io,
	mangle	=> qr/(FORWARD|(IN|OUT)PUT|(PRE|POST)ROUTING)/io,
	raw		=> qr/(PREROUTING|OUTPUT)/io,
);

sub make_ipv6_regex {
	# Taken from CPAN Regexp::IPv6 by Salvador Fandiño García
	my $IPv4 = "((25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))";
	my $G = "[0-9a-fA-F]{1,4}";

	my @tail = (
		":",
		"(:($G)?|$IPv4)",
		":($IPv4|$G(:$G)?|)",
		"(:$IPv4|:$G(:$IPv4|(:$G){0,2})|:)",
		"((:$G){0,2}(:$IPv4|(:$G){1,2})|:)",
		"((:$G){0,3}(:$IPv4|(:$G){1,2})|:)",
		"((:$G){0,4}(:$IPv4|(:$G){1,2})|:)" );

	my $IPv6_re = $G;
	$IPv6_re = "$G:($IPv6_re|$_)" for @tail;
	$IPv6_re = qq/:(:$G){0,5}((:$G){1,2}|:$IPv4)|$IPv6_re/;
	$IPv6_re =~ s/\(/(?:/g;
	#$IPv6_re = qr/$IPv6_re/;
	return $IPv6_re;
}


# constructor
sub new {
	my ($class) = @_;
	my $self = {
		_table => undef,			_chain => undef,		_target => undef,
		_eth_in => undef,			_eth_out => undef,		_src => undef,
		_dst => undef,				_protocol => undef,		_sport => undef,
		_dport => undef,			_comment => undef,		_sports => undef,
		_dports => undef,			_mac => undef,			_state => undef,
		_limit_packets => undef,	_limit_period => undef,	_limit_burst => undef,	# limit module
		_time_start => undef,		_time_finish => undef,	_time_days => undef,	# time module
		_src_range_start => undef,	_src_range_end => undef,						# iprange module
		_statistic_every => undef,	_statistic_offset => undef,						# statistic module
		_last_error => undef,
	};
	bless $self, $class;
	return $self;
}

# aliases
sub src			{ &source(@_); }
sub dst			{ &destination(@_); }
sub dest		{ &destination(@_); }
sub proto		{ &protocol(@_); }
sub sport		{ &source_port(@_); }
sub dport		{ &destination_port(@_); }
sub dest_port	{ &destination_port(@_); }
sub mac			{ &mac_address(@_); }

# accessor method
sub table {
	my ($self, $val) = @_;

	if (defined($val)) {
		undef $self->{_table};
		return unless ($val =~ m/\A$qr_tables\z/);
		$self->{_table} = $val;
	}

	return $self->{_table};
}
sub chain {
	my ($self, $val) = @_;

	if (defined($val)) {
		undef $self->{_chain};
		return unless ($self->{_table});
		return unless ($val =~ m/\A\w+\z/);
		$val = uc($val) if ($val =~ m/\A$qr_chains{$self->{_table}}\z/);
		$self->{_chain} = $val;
	}

	return $self->{_chain};
}
sub target {
	my ($self, $val) = @_;

	if (defined($val)) {
		undef $self->{_target};
		return unless ($val =~ m/\A\w+\z/);
		$val = uc($val) if ($val =~ m/\A$qr_builtins\z/);
		$self->{_target} = $val;
	}

	return $self->{_target};
}
sub source {
	my ($self, $val) = @_;

	if (defined($val)) {
		undef $self->{_src};
		# work out if this is an ip address, ip cidr, hostname or ip range
		if ($val =~ m/\A$qr_ip4_address\z/) {
			# IPv4 Address
			$self->{_src} = $val;
		}
		elsif ($val =~ m/\A$qr_ip4_cidr\z/) {
			# IPv4 CIDR
			$self->{_src} = $val;
		}
		elsif ($val =~ m/\A($qr_ip4_address)-($qr_ip4_address)\z/) {
			# IPv4 Range
			$self->{_src_range_start}	= $1;
			$self->{_src_range_end}		= $2;
		}
		elsif ($val =~ m/\A$qr_ip6_address\z/) {
			# IPv6 Address
			$self->{_src} = $val;
		}
		elsif ($val =~ m/\A$qr_ip6_cidr\z/) {
			# IPv6 Address
			$self->{_src} = $val;
		}
		elsif ($val =~ m/\A($qr_ip6_address)-($qr_ip6_address)\z/) {
			# IPv6 Range
			$self->{_src_range_start}	= $1;
			$self->{_src_range_end}		= $2;
		}
		elsif ($val =~ m/\A$qr_hostname\z/) {
			# Hostname
			$self->{_src} = $val;
		}
		else {
			# Something invalid
			return;
		}
	}

	return $self->{_src};
}
sub destination {
	my ($self, $val) = @_;

	if (defined($val)) {
		undef $self->{_dst};
		# work out if this is an ip address, ip cidr, hostname or ip range
		if ($val =~ m/\A$qr_ip4_address\z/) {
			# IP Address
			$self->{_dst} = $val;
		}
		elsif ($val =~ m/\A$qr_ip4_cidr\z/) {
			# IP CIDR
			$self->{_dst} = $val;
		}
		elsif ($val =~ m/\A($qr_ip4_address)-($qr_ip4_address)\z/) {
			# IP Range
			$self->{_dst_range_start}	= $1;
			$self->{_dst_range_end}		= $2;
		}
		elsif ($val =~ m/\A$qr_ip6_address\z/) {
			# IPv6 Address
			$self->{_dst} = $val;
		}
		elsif ($val =~ m/\A$qr_ip6_cidr\z/) {
			# IPv6 Address
			$self->{_dst} = $val;
		}
		elsif ($val =~ m/\A($qr_ip6_address)-($qr_ip6_address)\z/) {
			# IPv6 Range
			$self->{_dst_range_start}	= $1;
			$self->{_dst_range_end}		= $2;
		}
		elsif ($val =~ m/\A$qr_hostname\z/) {
			# Hostname
			$self->{_dst} = $val;
		}
		else {
			# Something invalid
			return;
		}
	}

	return $self->{_dst};
}
sub inbound {
	my ($self, $val) = @_;

	if (defined($val)) {
		undef $self->{_eth_in};
		return unless ($val =~ m/\A$qr_eth_name\z/);
		$self->{_eth_in} = $val;
	}

	return $self->{_eth_in};
}
sub outbound {
	my ($self, $val) = @_;

	if (defined($val)) {
		undef $self->{_eth_out};
		return unless ($val =~ m/\A$qr_eth_name\z/);
		$self->{_eth_out} = $val;
	}

	return $self->{_eth_out};
}
sub protocol {
	my ($self, $val) = @_;

	if (defined($val)) {
		undef $self->{_protocol};
		if ($val =~ m/\A$qr_protocols\z/) {
			$self->{_protocol} = lc($val);
		}
		if ($val =~ m/\A$qr_number\z/) {
			$self->{_protocol} = $val;
		}
		else {
			# Something invalid
			return;
		}
	}

	return $self->{_protocol};
}
sub source_port {
	my ($self, $val) = @_;

	if (defined($val)) {
		undef $self->{_spt};
		undef $self->{_spts};
		# is this a port, port list or port range?
		if ($val =~ m/\A$qr_port\z/) {
			$self->{_spt} = lc($val);
		}
		elsif ($val =~ m/\A$qr_port_list\z/) {
			$self->{_spts} = lc($val);
		}
		elsif ($val =~ m/\A$qr_port_range\z/) {
			$self->{_spts} = lc($val);
		}
		else {
			# Something invalid
			return;
		}
	}

	return $self->{_spt};
}
sub destination_port {
	my ($self, $val) = @_;

	if (defined($val)) {
		undef $self->{_dpt};
		undef $self->{_dpts};
		# is this a port, port list or port range?
		if ($val =~ m/\A$qr_port\z/) {
			$self->{_dpt} = lc($val);
		}
		elsif ($val =~ m/\A$qr_port_list\z/) {
			$self->{_dpts} = lc($val);
		}
		elsif ($val =~ m/\A$qr_port_range\z/) {
			$self->{_dpts} = lc($val);
		}
		else {
			# Something invalid
			return;
		}
	}

	return $self->{_dpt};
}
sub comment {
	my ($self, $val) = @_;

	if (defined($val)) {
		undef $self->{_comment};
		$val =~ s/"//g;	# strip quote characters
		$self->{_comment} = $val;
	}

	return $self->{_comment};
}
sub mac_address {
	my ($self, $val) = @_;

	if (defined($val)) {
		undef $self->{_mac};
		return unless ($val =~ m/\A$qr_mac_address\z/);
		$self->{_mac} = lc($val);
	}

	return $self->{_mac};
}
sub state {
	my ($self, $val) = @_;

	if (defined($val)) {
		undef $self->{_state};
		return unless ($val =~ m/\A$qr_tcp_states\z/);
		$self->{_state} = uc($val);
	}

	return $self->{_state};
}
sub icmp_type {
	my ($self, $val) = @_;

	if (defined($val)) {
		undef $self->{_icmp_type};
		$self->{_icmp_type} = $val;
	}

	return $self->{_icmp_type};
}
### iptables module: time
sub limit_packets {
	my ($self, $val) = @_;

	if (defined($val)) {
		undef $self->{_limit_packets};
		return unless ($val =~ m/\A$qr_number\z/);
		$self->{_limit_packets} = $val;
	}

	return $self->{_limit_packets};
}
sub limit_period {
	my ($self, $val) = @_;

	if (defined($val)) {
		undef $self->{_limit_period};
		return unless ($val =~ m/\A(second|minute|hour|day)\z/i);
		$self->{_limit_period} = $val;
	}

	return $self->{_limit_period};
}
sub limit_burst {
	my ($self, $val) = @_;

	if (defined($val)) {
		undef $self->{_limit_burst};
		return unless ($val =~ m/\A$qr_number\z/);
		$self->{_limit_burst} = $val;
	}

	return $self->{_limit_burst};
}
sub limit {
	my ($self, $pkts, $period, $burst) = @_;

	if (defined($pkts)) {
		return unless $self->_limit_packets($pkts);
	}
	if (defined($period)) {
		return unless $self->_limit_period($period);
	}
	if (defined($burst)) {
		return unless $self->_limit_burst($burst);
	}

	return ($self->limit_packets, $self->limit_period, $self->limit_burst);
}
### iptables module: time
sub date_start {
	my ($self, $val) = @_;

	# ISO 8601 "T" notation: 1970-01-01T00:00:00 to 2038-01-19T04:17:07
	if (defined($val)) {
		undef $self->{_date_start};
		return unless ($val =~ m/\A$qr_iso8601\z/);
		$self->{_date_start} = $val;
	}

	return $self->{_date_start};
}
sub date_finish {
	my ($self, $val) = @_;

	if (defined($val)) {
		undef $self->{_date_finish};
		return unless ($val =~ m/\A$qr_iso8601\z/);
		$self->{_date_finish} = $val;
	}

	return $self->{_date_finish};
}
sub time_start {
	my ($self, $val) = @_;

	if (defined($val)) {
		undef $self->{_time_start};
		return unless ($val =~ m/\A$qr_time24\z/);
		$self->{_time_start} = $val;
	}

	return $self->{_time_start};
}
sub time_finish {
	my ($self, $val) = @_;

	if (defined($val)) {
		undef $self->{_time_finish};
		return unless ($val =~ m/\A$qr_time24\z/);
		$self->{_time_finish} = $val;
	}

	return $self->{_time_finish};
}
sub time_weekdays {
	my ($self, $val) = @_;

	if (defined($val)) {
		undef $self->{_time_weekdays};
		return unless ($val =~ m/\A$qr_weekdays\z/);
		$self->{_time_weekdays} = $1;
	}

	return $self->{_time_weekdays};
}
sub time {
	my ($self, $start, $finish, $weekdays) = @_;

	if (defined($start)) {
		return unless $self->_time_start($start);
	}
	if (defined($finish)) {
		return unless $self->_time_finish($finish);
	}
	if (defined($weekdays)) {
		return unless $self->_time_weekdays($weekdays);
	}

	return ($self->time_start, $self->time_finish, $self->time_weekdays);
}
### iptables module: statistic
sub every {
	my ($self, $every) = @_;

	if (defined($every)) {
		undef $self->{_statistic_every};
		return unless ($every =~ m/\A$qr_number\z/);
		$self->{_statistic_every} = $every;
	}

	return $self->{_statistic_every};
}
sub offset {
	my ($self, $offset) = @_;

	if (defined($offset)) {
		undef $self->{_statistic_offset};
		return unless ($offset =~ m/\A$qr_number\z/);
		$self->{_statistic_offset} = $offset;
	}

	return $self->{_statistic_offset};
}

sub compile {
	my ($self) = @_;

	# sanity checking
	unless ($self->{_table}) {
		$self->{_last_error} = 'Set table before compiling';
		return;
	}
	unless ($self->{_chain}){
		$self->{_last_error} = 'Set chain before compiling';
		return;
	}
	if (!$self->protocol or $self->protocol !~ m/(tcp|udp)/i) {
		if ($self->{_spt} or $self->{_dpt} or $self->{_spts} or $self->{_dpts}) {
			$self->{_last_error} = 'Port matching is only valid with TCP and UDP protocols';
			return;
		}
	}

	# anything ip version specific?
	my $version_reqd;		# IP Version of the rule
	foreach my $k qw/_src _src_range_start _src_range_end _dst _dst_range_start _dst_range_end/ {
		my $this_addr_version;	# IP Version of this address

		next unless ($self->{$k});

		my $addr = $self->{$k};
		undef $this_addr_version;
		if ($addr =~ m/\A($qr_ip4_address|$qr_ip4_cidr|$qr_ip4_address-$qr_ip4_address)\z/) {
			# IPv4
			$this_addr_version = 4;
		} elsif ($addr =~ m/\A($qr_ip6_address|$qr_ip6_cidr|$qr_ip6_address-$qr_ip6_address)\z/) {
			# IPv6
			$this_addr_version = 6;
		}

		# OK? OK.
		if ($version_reqd and $this_addr_version != $version_reqd) {
			$self->{_last_error} = sprintf(
				'Mixing of IP Protocols not possible. Detected [%s] as IPv%u but found another address for IPv%u',
				$addr,
				$this_addr_version,
				$version_reqd
			);
			return;
		} else {
			$version_reqd = $this_addr_version;
		}
	}
	if ($self->{_protocol}) {
		if ($self->{_protocol} eq 'icmp') {
			# IPv4
			if ($version_reqd and $version_reqd != 4) {
				$self->{_last_error} = 'Protocol [ICMP] requires IPv4';
				return;
			}
			$version_reqd = 4;
		}
		if ($self->{_protocol} eq 'icmpv6') {
			# IPv4
			if ($version_reqd and $version_reqd != 6) {
				$self->{_last_error} = 'Protocol [ICMPv6] requires IPv6';
				return;
			}
			$version_reqd = 6;
		}
	}
	# assume ipv4 after this point unless already set to ipv6
	$version_reqd = 4 unless ($version_reqd);
	if ($self->{_icmp_type}) {
		# Make icmp_type take precedence over the protocol; ignore whatever
		# protocol was previously set and force it to the appropriate icmp(v6)
		$self->{_protocol} = ($version_reqd == 4) ? 'icmp' : 'icmpv6';
	}

	# aggregate criteria that is part of a single module to one usage of the module
	$self->{_time} = undef;
	$self->{_time} .= "--datestart $self->{_date_start}"	if (defined($self->{_date_start}));
	$self->{_time} .= "--datestop $self->{_date_finish}"	if (defined($self->{_date_start}));
	$self->{_time} .= "--timestart $self->{_time_start}"	if (defined($self->{_time_start}));
	$self->{_time} .= "--timestop $self->{_time_finish}"	if (defined($self->{_time_start}));
	$self->{_time} .= "--weekdays $self->{_time_weekdays}"	if (defined($self->{_time_weekdays}));

	$self->{_statistic} = undef;
	$self->{_statistic} .= "--mode nth --every $self->{_statistics_every}"	if (defined($self->{_statistics_every}));
	$self->{_statistic} .= "--packet $self->{_statistics_offset}"			if (defined($self->{_statistics_offset}));

	$self->{_limit} = undef;
	$self->{_limit} .= "--limit $self->{_limit_packets}"		if (defined($self->{_limit_packets}));
	$self->{_limit} .= "--limit-burst $self->{_limit_burst}"	if (defined($self->{_limit_burst}));

	my $ipt_rule;
	$ipt_rule .= sprintf(' -j %s', $self->target)		if (defined($self->target));
	$ipt_rule .= sprintf(' -p %s', $self->proto)		if (defined($self->proto));
	if ($self->{_icmp_type}) {
		$ipt_rule .= sprintf(' %s %s',	# This is special because the syntax is different between IPv4 and IPv6
			($version_reqd == 4) ? '--icmp-type' : '--icmpv6-type',
			$self->icmp_type);
	}
	$ipt_rule .= sprintf(' -i %s', $self->inbound)		if (defined($self->inbound));
	$ipt_rule .= sprintf(' -o %s', $self->outbound)		if (defined($self->outbound));
	$ipt_rule .= sprintf(' -s %s', $self->{_src})		if (defined($self->{_src}));
	$ipt_rule .= sprintf(' -d %s', $self->{_dst})		if (defined($self->{_dst}));
	$ipt_rule .= sprintf(' --sport %s',	$self->{_spt})	if (defined($self->{_spt}));
	$ipt_rule .= sprintf(' --dport %s',	$self->{_dpt})	if (defined($self->{_dpt}));
	$ipt_rule .= sprintf(' -m multiport --sports %s',	$self->{_spts})		if (defined($self->{_spts}));
	$ipt_rule .= sprintf(' -m multiport --dports %s',	$self->{_dpts})		if (defined($self->{_dpts}));
	$ipt_rule .= sprintf(' -m mac --mac-source %s',		$self->mac)			if (defined($self->mac));
	$ipt_rule .= sprintf(' -m limit %s',				$self->{_limit})	if (defined($self->{_limit}));
	$ipt_rule .= sprintf(' -m state --state %s',		$self->state)		if (defined($self->state));
	$ipt_rule .= sprintf(' -m statistic %s',			$self->{_statistic})if (defined($self->{_statistic}));
	$ipt_rule .= sprintf(' -m iprange --src-range %s',	$self->{_srcrange})	if (defined($self->{_srcrange}));
	$ipt_rule .= sprintf(' -m iprange --dst-range %s',	$self->{_dstrange})	if (defined($self->{_dstrange}));
	$ipt_rule .= sprintf(' -m time %s',					$self->{_time})		if (defined($self->{_time}));
	$ipt_rule .= sprintf(' -m comment --comment "%s"',	$self->comment)		if (defined($self->comment));

	# Make sure we have criteria set
	unless ($ipt_rule) {
		$self->{_last_error} = 'No criteria or action set';
		return;
	}

	# All good! Pass back the compiled rule
	return sprintf('-t %s -A %s%s', $self->table, $self->chain, $ipt_rule);
}

sub truncate {
	my ($self) = @_;

	foreach my $k (keys %{$self}) {
		undef $self->{$k} if ($k =~ m/\A_/);
	}

	return 1;
}

sub last_error {
	my ($self) = @_;
	return $self->{_last_error} if $self->{_last_error};
	return;
}

package IPTables::Rule::IPv4;
use strict;
use warnings;
our @ISA = qw(IPTables::Rule);    # inherits from IPTables::Rule

# constructor
sub new {
	my ($class) = @_;

	# call the constructor of the parent class.
	my $self = $class->SUPER::new();

#	$self->{_something}	= undef;
#	$self->{_title}		= undef;

	bless $self, $class;
	return $self;
}

###############################################################################

package main;

use strict;
use warnings;

my $ipt_rule = IPTables::Rule->new;

$ipt_rule->table('filter');
$ipt_rule->chain('OUTPUT');
$ipt_rule->source('1.2.3.4');
$ipt_rule->src('4.3.2.1');
$ipt_rule->proto('tcp');
$ipt_rule->dest_port('21');
$ipt_rule->target('accept');

for my $d qw/Mon mon Monday tue,th sat,sun sat,sun,mon wed fr fake noaday/ {
	print("===> $d\n");
	$ipt_rule->time_weekdays($d);
	print(($ipt_rule->compile() or $ipt_rule->last_error)."\n");
}

$ipt_rule->truncate;
$ipt_rule->table('filter');
$ipt_rule->chain('FORWArd');
$ipt_rule->src('192.168.1.1');
$ipt_rule->dest('2001::de:ad:be:ef');
print(($ipt_rule->compile() or $ipt_rule->last_error)."\n");

$ipt_rule->truncate;
$ipt_rule->table('filter');
$ipt_rule->chain('inpuasdfasdft');
$ipt_rule->target('accept');
$ipt_rule->dest('2001::de:ad:be:ef');
$ipt_rule->icmp_type('icmp-echo-request') or print "bullshit rejected\n";
$ipt_rule->time_weekdays('Wednesday');
print(($ipt_rule->compile() or $ipt_rule->last_error)."\n");

exit 0;
