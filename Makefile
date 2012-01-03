### The project name
PROJECT=husk

### Dependencies
DEP_BINS=perl iptables iptables-save iptables-restore mktemp cat grep bash
DEP_PMODS=File::Basename Config::Simple Config::IniFiles Getopt::Long

### Destination Paths
D_BIN=/usr/local/sbin
D_DOC=/usr/local/share/doc/$(PROJECT)
D_MAN=/usr/local/share/man
D_CNF=/etc/$(PROJECT)
D_HELPERS=$(D_CNF)/helpers

### Lists of files to be installed
F_CONF=husk.conf interfaces.conf addr_groups.conf
F_HELPERS=icmp.conf icmpv6.conf samba.conf apple-ios.conf avg.conf dhcp.conf \
		  dhcpv6.conf mail.conf dns.conf snmp.conf sql.conf gotomeeting.conf \
		  pptp.conf nfs.conf
F_DOCS=ABOUT README rules.conf.simple rules.conf.standalone LICENSE

fb_dir=.husk-fallback-$(shell date +%Y%m%d%H%M%S)

###############################################################################

all: install

install: test bin docs config
	# install the actual scripts
	install -D -m 0755 src/$(PROJECT).pl $(DESTDIR)$(D_BIN)/$(PROJECT)
	install -D -m 0755 src/fire.sh $(DESTDIR)$(D_BIN)/fire
	# install documentation
	for f in $(F_DOCS) ; do \
		install -D -m 0644 $$f $(DESTDIR)$(D_DOC)/$$f || exit 1 ; \
	done
	install -Dm0644 husk.1.man $(DESTDIR)$(D_MAN)/man1/husk.1p
	install -Dm0644 fire.1.man $(DESTDIR)$(D_MAN)/man1/fire.1p

fallback:
	mkdir $(fb_dir)
	cp $(DESTDIR)$(D_BIN)/$(PROJECT) $(fb_dir)/
	cp $(DESTDIR)$(D_BIN)/fire $(fb_dir)/
	for f in $(F_DOCS) ; do \
		cp $(DESTDIR)$(D_DOC)/$$f $(fb_dir)/ || exit 1 ; \
	done
	@echo "IF THE NEXT COMMANDS FAIL, THAT IS OK"
	@cp $(DESTDIR)$(D_MAN)/man1/husk.1p $(fb_dir)/ || true
	@cp $(DESTDIR)$(D_MAN)/man1/fire.1p $(fb_dir)/ || true

test:
	@echo "==> Checking for required external dependencies"
	for bindep in $(DEP_BINS) ; do \
		which $$bindep > /dev/null || exit 1 ; \
	done

	@echo "==> Checking for required perl modules"
	for pmod in $(DEP_PMODS) ; do \
		perl -M$$pmod -e 1 || exit 1 ; \
	done

	@echo "==> Checking for valid script syntax"
	@perl -c src/husk.pl
	@bash -n src/fire.sh

	@echo "==> It all looks good Captain!"

bin: test src/$(PROJECT).pl src/fire.sh

docs: $(F_DOCS)
	pod2man --name=husk src/husk.pl husk.1.man
	pod2man --name=fire fire.pod fire.1.man

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
