### The project name
PROJECT=husk

### Dependencies
DEP_BINS=perl iptables iptables-save iptables-restore mktemp cat grep bash
DEP_PMODS=File::Basename Config::Simple Config::IniFiles Getopt::Long Net::DNS

### Destination Paths
D_BIN=/usr/local/sbin
D_DOC=/usr/local/share/doc/$(PROJECT)
D_MAN=/usr/local/share/man
D_CNF=/etc/$(PROJECT)
D_HELPERS=$(D_CNF)/helpers

### Lists of files to be installed
F_CONF=husk.conf interfaces.conf addr_groups.conf
F_HELPERS=icmp.conf samba.conf apple-ios.conf avg.conf dhcp.conf mail.conf \
		  dns.conf snmp.conf sql.conf gotomeeting.conf pptp.conf
F_DOCS=ABOUT README rules.conf.simple rules.conf.standalone LICENSE

###############################################################################

all: install

install: test bin docs config
	# install the actual scripts
	install -D -m 0755 $(PROJECT).pl $(DESTDIR)$(D_BIN)/$(PROJECT)
	install -D -m 0755 fire.sh $(DESTDIR)$(D_BIN)/fire
	# install documentation
	for f in $(F_DOCS) ; do \
		install -D -m 0644 $$f $(DESTDIR)$(D_DOC)/$$f || exit 1 ; \
	done
	install -Dm0644 husk.1.man $(DESTDIR)$(D_MAN)/man1/husk.1p

test:
	@echo "==> Checking for required external dependencies"
	for bindep in $(DEP_BINS) ; do \
		which $$bindep > /dev/null || exit 1 ; \
	done

	@echo "==> Checking for required perl modules"
	for pmod in $(DEP_PMODS) ; do \
		perl -M$$pmod -e 1 || exit 1 ; \
	done
	@echo "==> It all looks good Captain!"

bin: test $(PROJECT).pl fire.sh

docs: $(F_DOCS)
	pod2man --name=husk husk.pl husk.1.man

config: $(F_CONF)
	# Install Distribution Helper Rule Files
	for f in $(F_HELPERS) ; do \
		install -D -m 0444 helpers/$$f $(DESTDIR)$(D_HELPERS)/$$f || exit 1 ; \
	done
	# Install (without overwriting) configuration files
	for f in $(F_CONF) ; do \
		[[ -e $(DESTDIR)$(D_CNF)/$$f ]] || \
			install -D -m 0644 $$f $(DESTDIR)$(D_CNF)/$$f ; \
	done

uninstall:
	rm -f $(DESTDIR)$(D_MAN)/man1/husk.1p
	rm -f $(DESTDIR)$(D_BIN)/$(PROJECT)
	rm -f $(DESTDIR)$(D_BIN)/fire
	rm -f $(DESTDIR)$(D_DOC)/*
	rmdir $(DESTDIR)$(D_DOC)/
	echo "Leaving '$(DESTDIR)$(D_CNF)' untouched"
