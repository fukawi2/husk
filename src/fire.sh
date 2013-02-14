#!/bin/bash

# Copyright (C) 2010-2013 Phillip Smith
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

function compile_rules {
  local _command="$1"
  local _temp_file="$2"

  if $_command &> "$_temp_file" ; then
    # success, return
    return 0
  fi

  # compilation did not succeed, show error and die
  echo 'Error compiling ruleset:' >&2
  cat $_temp_file
  logger -t husk-fire -p user.warning -- 'Error during compilation :('
  cleanup
  exit 3
}

function save_live_rules {
  local _ipt_save="$1"
  local _fname="$2"

  if $_ipt_save &> "$_fname" ; then
    # success
    return 0
  fi

  # something went wrong; try and work out why
  if ! grep -q ipt /proc/modules 2>/dev/null ; then
    echo "You don't appear to have iptables support in your kernel." >&2
    cleanup
    exit 5
  else
    echo "Unknown error saving current iptables ruleset." >&2
    cleanup
    exit 255
  fi
}

function apply_rules {
  # this function lets us reuse some logic and error checking
  # for loading both ipv4 and ipv6 rules.
  local _ipt_restore="$1"
  local _fname="$2"

  # do a test restore first to see if there are errors
  local _test_output=$($_ipt_restore --test < $_fname 2>&1)

  # how did we go?
  if [[ -n "$_test_output" ]] ; then
    # test restore reevaled an error
    echo "   ERROR: The following line was not accepted by the kernel" >&2
    local _failed_line=$(perl -ne '$_ =~ /line:? (\d+)/m; print $1;' <<< $_test_output)
#    echo "DEBUG: _test_output = $_test_output"
#    echo "DEBUG: _failed_line = $_failed_line"
    echo -n '   ' ; sed -n "${_failed_line}p" $_fname >&2
    cleanup
    exit 5
  fi

  # seems the test went ok, so now we can do the actual apply
  $_ipt_restore < $_fname
  return $?
}

function revert_rulesets {
  local _v4_savefile="$1"
  local _v6_savefile="$2"

  [[ $IPv4 -eq 1 ]] && iptables-restore   < "$_v4_savefile"
  [[ $IPv6 -eq 1 ]] && ip6tables-restore  < "$_v6_savefile"

  return 0
}

function make_suggestions {
  rfile='/etc/husk/rules.conf'
  [[ -f $rfile ]] || { echo "$rfile not found" ; return 1; }
  [[ -r $rfile ]] || { echo "$rfile not readable" ; return 1; }
  # check for missing "common" rules
  grep -qPi '^\s*common\s+loopback' $rfile || echo 'MISSING: common loopback'
  grep -qPi '^\s*common\s+spoof'    $rfile || echo 'MISSING: common spoof LAN x.x.x.x/yy'
  grep -qPi '^\s*common\s+bogon'    $rfile || echo 'MISSING: common bogon NET'
  grep -qPi '^\s*common\s+portscan' $rfile || echo 'MISSING: common portscan NET'
  grep -qPi '^\s*common\s+xmas'     $rfile || echo 'MISSING: common xmas NET'
  grep -qPi '^\s*common\s+syn'      $rfile || echo 'MISSING: common syn NET'
  # check for use of sub-routines
  if ! grep -qPi '^\s*define\s+rules\s+\S+$' $rfile ; then
    echo '============================================================'
    printf "%10s %s\n" 'Problem:' 'No subroutines found.'
    printf "%10s %s\n" 'Risk:' 'Subroutines help make your rules more efficient.'
    printf "%10s %s\n" 'Suggest:' 'Consolidate repeated rules into subroutines. Refer to docs for further infomation.'
  fi
  # check for logging without rate-limiting
  log_lines=$(grep -Pi '^\s*log\s+' $rfile)
  if [[ -n "$log_lines" ]] ; then
    # found log lines...
    if ! grep -qPi '\s+limit\s+' <<< $log_lines ; then
      # ...but not rate-limited
      echo '============================================================'
      printf "%10s %s\n" 'Problem:' 'You appear to have 1 or more logging rules that are not rate-limited.'
      printf "%10s %s\n" 'Risk:' 'This could cause a Denial-of-Service (DOS) against your rule sets'
      printf "%10s %s\n" 'Suggest:' 'Apply a rate-limit to logging rules. eg: "limit 3/sec"'
    fi
  fi
}

function cleanup() {
  rm -f "$IPv4_FILE" "$IPv6_FILE" || true
  rm -f "$S4FILE" "$S6FILE" || true
}
trap cleanup INT TERM EXIT


###############################################################################
### Start of actual execution code
###############################################################################

set -u
set -e

TIMEOUT=10
IP4_CHECK="/proc/$$/net/ip_tables_names"
IP6_CHECK="/proc/$$/net/ip6_tables_names"
skip_confirm=0

if [ $EUID -ne 0 ] ; then
  echo "You are using a non-privileged account"
  exit 1
fi

# we need some temp files
IPv4_FILE=$(mktemp -t husk-firev4.XXX)
IPv6_FILE=$(mktemp -t husk-firev6.XXX)
S4FILE=$(mktemp -t husk-fire-savev4.XXX)
S6FILE=$(mktemp -t husk-fire-savev6.XXX)

# Check we've got all our dependencies
export PATH='/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin'
for ebin in iptables-save iptables-restore husk mktemp cat grep logger printf sed ; do
  [[ -z "$(which $ebin 2>/dev/null)" ]] && { echo "Could not locate '$ebin'" >&2; exit 1; }
done

### process command line options
while getopts "fs" opt; do
  case $opt in
  f)
    skip_confirm=1
    ;;
  s)
    make_suggestions
    exit 0
    ;;
  *)
    echo "Invalid option: -$OPTARG" >&2
    exit 1
    ;;
  esac
done

# What do we have support for?
IPv4=0
IPv6=0
[[ -e $IP4_CHECK ]] && { IPv4=1; logger -t husk-fire -p user.debug -- 'IPv4 (iptables) support appears to be present'; }
[[ -e $IP6_CHECK ]] && { IPv6=1; logger -t husk-fire -p user.debug -- 'IPv6 (ip6tables) support appears to be present'; }

# Compile ruleset to a temporary file ready to test loading
# note that compile_rules() will die if there is an error so
# there is no need to error check here.
echo 'Compiling rulesets...'
if [[ $IPv4 -eq 1 ]] ; then
  echo '   => IPv4'
  logger -t husk-fire -p user.info -- 'Compiling IPv4 rules'
  compile_rules 'husk -4' $IPv4_FILE
fi
if [[ $IPv6 -eq 1 ]] ; then
  echo '   => IPv6'
  logger -t husk-fire -p user.info -- 'Compiling IPv6 rules'
  compile_rules 'husk -6' $IPv6_FILE
fi

# save the current rules to a temporary file in case we need
# to restore to a known good state.
echo 'Saving current rulesets...'
if [[ $IPv4 -eq 1 ]] ; then
  echo '   => IPv4'
  save_live_rules iptables-save  $S4FILE
fi
if [[ $IPv6 -eq 1 ]] ; then
  echo '   => IPv6'
  save_live_rules ip6tables-save $S6FILE
fi

# attempt to apply new rules
echo 'Applying new rulesets...'
if [[ $IPv4 -eq 1 ]] ; then
  echo '   => IPv4'
  logger -t husk-fire -p user.info -- 'Applying compiled IPv4 rules'
  apply_rules iptables-restore $IPv4_FILE
fi
if [[ $IPv6 -eq 1 ]] ; then
  echo '   => IPv6'
  logger -t husk-fire -p user.info -- 'Applying compiled IPv6 rules'
  apply_rules ip6tables-restore $IPv6_FILE
fi

# Get user confirmation that it's all OK (unless asked not to)
if [ "$skip_confirm" == '0' ] ; then
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
      revert_rulesets $S4FILE $S6FILE
      cleanup
      exit 255
      ;;
  esac
fi

# user feedback
iptables -S &> /dev/null
if [[ $? -eq 0 ]] ; then
  if [[ $IPv4 -eq 1 ]] ; then
    ip4chains=$( ( for T in filter nat mangle raw ; do iptables -t $T -S ; done )  | grep -Pc '^-N' )
    ip4rules=$( ( for T in filter nat mangle raw ;  do iptables -t $T -S ; done )  | grep -Pc '^-A' )
    msg=$(printf 'IPv4: Loaded %u rules in %u chains.\n' $ip4rules $ip4chains)
    echo $msg
    logger -t husk-fire -p user.info -- $msg
  fi
  if [[ $IPv6 -eq 1 ]] ; then
    ip6chains=$( ( for T in filter mangle raw ; do ip6tables -t $T -S ; done ) | grep -Pc '^-N' )
    ip6rules=$( ( for T in filter mangle raw ;  do ip6tables -t $T -S ; done ) | grep -Pc '^-A' )
    msg=$(printf 'IPv6: Loaded %u rules in %u chains.\n' $ip6rules $ip6chains)
    echo $msg
    logger -t husk-fire -p user.info -- $msg
  fi
fi

# save to init script file if possible
[[ -f '/etc/redhat-release' ]]  && file4='/etc/sysconfig/iptables'
[[ -f '/etc/redhat-release' ]]  && file6='/etc/sysconfig/ip6tables'
[[ -f '/etc/debian_version' ]]  && file4='/etc/iptables.rules'
[[ -f '/etc/debian_version' ]]  && file6='/etc/ip6tables.rules'
[[ -f '/etc/arch-release' ]]    && file4='/etc/iptables/iptables.rules'
[[ -f '/etc/arch-release' ]]    && file6='/etc/iptables/ip6tables.rules'
if [[ -n "$file4" && -n "$file6" ]] ; then
  # we have somewhere to save the rules to
  iptables-save > $file4
  ip6tables-save > $file6
else
  echo "WARNING: Unable to save rules; could not determine distribution"
fi

exit 0
