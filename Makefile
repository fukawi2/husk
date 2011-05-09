### The project name
PROJECT=husk

### Dependencies
DEP_BINS=perl iptables iptables-save iptables-restore mktemp cat grep bash
DEP_PMODS=File::Basename Config::Simple Config::IniFiles Getopt::Long

### Destination Paths
D_BIN=/usr/local/sbin
D_DOC=/usr/local/share/doc/$(PROJECT)
D_CNF=/etc/$(PROJECT)
D_HELPERS=$(D_CNF)/helpers/

### Lists of files to be installed
F_CONF=husk.conf interfaces.conf addr_groups.conf
F_HELPERS=icmp.conf samba.conf apple-ios.conf avg.conf dhcp.conf mail.conf \
		  dns.conf snmp.conf sql.conf gotomeeting.conf pptp.conf
F_DOCS=ABOUT README rules.conf.simple rules.conf.standalone LICENSE

###############################################################################

all: install

install: test bin docs config

test:
	@echo "==> Checking for required external dependencies"
	for bindep in $(DEP_BINS) ; do \
		which $$bindep > /dev/null ; \
	done

	@echo "==> Checking for required perl modules"
	for pmod in $(DEP_PMODS) ; do \
		perl -M$$pmod -e 1 ; \
	done
	@echo "==> It all looks good Captain!"

bin: test $(PROJECT).pl fire.sh
	install -D -m 0755 $(PROJECT).pl $(DESTDIR)$(D_BIN)/$(PROJECT)
	install -D -m 0755 fire.sh $(DESTDIR)$(D_BIN)/fire

docs: $(F_DOCS)
	for f in $(F_DOCS) ; do \
		install -D -m 0644 $$f $(DESTDIR)$(D_DOC)/$$f ; \
	done

config: $(F_CONF) $(F_HELPERS)
	# Install Distribution Helper Rule Files
	for f in $(HELPERS) ; do \
		install -D -m 0444 helpers/$$f $(DESTDIR)$(D_HELPERS)/$$f ; \
	done
	# Install (without overwriting) configuration files
	for f in $(F_CONF) ; do \
		[[ -e $(DESTDIR)$(D_CNF)/$$f ]] || \
			install -D -m 0644 $$f $(DESTDIR)$(D_CNF)/$$f ; \
	done

uninstall:
	rm -f $(DESTDIR)$(D_BIN)/$(PROJECT)
	rm -f $(DESTDIR)$(D_BIN)/fire
	rm -f $(DESTDIR)$(D_DOC)/*
	rmdir $(DESTDIR)$(D_DOC)/
	echo "Leaving '$(DESTDIR)$(D_CNF)' untouched"
