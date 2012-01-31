#!/bin/bash

# Copyright (C) 2010-2012 Phillip Smith
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

# Part of this script is based on the 'iptables-apply' script written
# by Martin F. Krafft <madduck@madduck.net> and distributed under the
# Artistic Licence 2.0

if [ $EUID -ne 0 ] ; then
	echo "You are using a non-privileged account"
	exit 1
fi

# Get command line args
args=("$@")

TIMEOUT=10

trap "rm -f $TFILE; rm -f $SFILE" EXIT 1 2 3 4 5 6 7 8 10 11 12 13 14 15

# Check we've got all our dependencies
export PATH='/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin'
for ebin in iptables-save iptables-restore husk mktemp cat grep logger printf ; do
	[[ -z "$(which $ebin 2>/dev/null)" ]] && { echo "Could not locate '$ebin'" >&2; exit 1; }
done
TFILE=$(mktemp -t husk-fire.XXX)
SFILE=$(mktemp -t husk-fire-save.XXX)

# Compile ruleset to a temporary file
echo 'Compiling rules.... '
logger -t husk-fire -p user.info -- 'Beginning compilation'
if "husk" $@ &> "$TFILE" ; then
    echo '   DONE'
	logger -t husk-fire -p user.info -- 'Compilation complete'
else
    echo 'Error compiling ruleset:' >&2
	cat "$TFILE" >&2
    exit 3
fi

# Save current ruleset to a temporary file
echo "Saving current rules.... "
if iptables-save > "$SFILE" ; then
    echo '   DONE'
else
	if ! grep -q ipt /proc/modules 2>/dev/null ; then
		echo "You don't appear to have iptables support in your kernel." >&2
		exit 5
	else
		echo "Unknown error saving current iptables ruleset." >&2
		exit 255
	fi
fi

# Apply the new rules
echo "Activating rules...."
logger -t husk-fire -p user.info -- 'Activating compiled rules'
activation_output=$(/bin/bash $TFILE)

# How did we go?
if [[ -n "$activation_output" ]] ; then
	# uhoh, generated some output...
	logger -s -t husk-fire -p user.warning <<< $activation_output
fi

# Get user confirmation that it's all OK (unless asked not to)
if [ "${args[0]}" != '--no-confirm' ] ; then
	echo -n "Can you establish NEW connections to the machine? (y/N) "
	read -n1 -t "${TIMEOUT}" ret 2>&1 || :
	echo
	case "${ret:-}" in
		y*|Y*)
			echo "Thank-you, come again!"
			logger -t husk-fire -p user.info -- 'New firewall rules loaded!'
			;;
		*)
			if [[ -z "${ret}" ]]; then
				echo "Uh-oh... Timeout waiting for reply!" >&2
				logger -t husk-fire -p user.info -- 'Timeout waiting for user confirmation of rules; ROLL BACK INITIATED'
			fi
			echo "Reverting to saved rules..." >&2
			iptables-restore < "$SFILE";
			exit 255
			;;
	esac
fi

# user feedback
iptables -S &> /dev/null
if [[ $? -eq 0 ]] ; then
  ip4chains=$( ( for T in filter nat mangle raw ; do iptables -t $T -S ; done )  | grep -Pc '^-N' )
  ip6chains=$( ( for T in filter mangle raw ;     do ip6tables -t $T -S ; done ) | grep -Pc '^-N' )
  ip4rules=$( ( for T in filter nat mangle raw ;  do iptables -t $T -S ; done )  | grep -Pc '^-A' )
  ip6rules=$( ( for T in filter mangle raw ;      do ip6tables -t $T -S ; done ) | grep -Pc '^-A' )
  printf 'IPv4: %u rules in %u chains.\n' $ip4rules $ip4chains
  printf 'IPv6: %u rules in %u chains.\n' $ip6rules $ip6chains
fi

# Save to init script file if possible
saved=0
for init_script in 'iptables' 'ip6tables' ; do
	for init_path in '/etc/init.d' '/etc/rc.d' ; do
		if [[ -x "$init_path/$init_script" ]] ; then
			logger -t husk-fire -p user.debug -- "Found executable script '$init_path/$init_script'; Calling with 'save' argument"
			$init_path/$init_script save > /dev/null
			saved=1
			break
		fi
	done
done
if [[ $saved != 1 ]]  ; then
	# Debian perhaps that doesn't have an iptables init script?
	[[ -n "$(which iptables-save)" ]]	&& iptables-save > /etc/iptables.rules
	[[ -n "$(which ip6tables-save)" ]]	&& ip6tables-save > /etc/ip6tables.rules
fi

exit 0
