#!/bin/bash

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
IPT_SAVE=`which iptables-save 2>/dev/null`
IPT_RESTORE=`which iptables-restore 2>/dev/null`
HUSK=`which husk 2>/dev/null`
TFILE=`mktemp -t husk-fire.XXX`
SFILE=`mktemp -t husk-fire-save.XXX`

trap "rm -f $TFILE; rm -f $SFILE" EXIT 1 2 3 4 5 6 7 8 10 11 12 13 14 15

# Check we've got all our dependencies
if [ ! -e "$HUSK" ] ; then
	echo "Could not locate 'husk'" >&2
	exit 1
fi
if [ ! -e "$IPT_SAVE" ] ; then
	echo "Could not locate 'iptables-save'" >&2
	exit 1
fi
if [ ! -e "$IPT_RESTORE" ] ; then
	echo "Could not locate 'iptables-restore'" >&2
	exit 1
fi
# ... and that they are executable
if [ ! -x "$HUSK" ] ; then
	echo "Found 'husk' but it is not executable: $HUSK" >&2
	exit 2
fi
if [ ! -x "$IPT_SAVE" ] ; then
	echo "Found 'iptables-save' but it is not executable: $IPT_SAVE" >&2
	exit 2
fi
if [ ! -x "$IPT_RESTORE" ] ; then
	echo "Found 'iptables-restore' but it is not executable: $IPT_RESTORE" >&2
	exit 2
fi

# Compile ruleset to a temporary file
echo 'Compiling rules.... '
if "$HUSK" $@ &> "$TFILE" ; then
    echo '   DONE'
else
    echo 'Error compiling ruleset:' >&2
	cat "$TFILE" >&2
    exit 3
fi

# Save current ruleset to a temporary file
echo "Saving current rules.... "
if "$IPT_SAVE" > "$SFILE" ; then
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
/bin/bash $TFILE

if [ "${args[0]}" == '--no-confirm' ] ; then
	echo -n "Can you establish NEW connections to the machine? (y/N) "
	read -n1 -t "${TIMEOUT}" ret 2>&1 || :
	echo
	case "${ret:-}" in
		y*|Y*)
			echo "Thank-you, come again!"
			;;
		*)
			if [[ -z "${ret}" ]]; then
				echo "Uh-oh... Timeout waiting for reply!" >&2
			fi
			echo "Reverting to saved rules..." >&2
			"$IPT_RESTORE" < "$SFILE";
			exit 255
			;;
	esac
fi

exit 0
