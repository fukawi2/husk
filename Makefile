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
F_DOCS=README doc/ABOUT doc/LICENSE doc/rules.conf.simple \
	   doc/rules.conf.standalone
F_MAN=man/*

fb_dir=.fallback-$(shell date +%Y%m%d%H%M%S)

###############################################################################

all: install

install: test bin docs config
	# install the actual scripts
	install -D -m 0755 src/$(PROJECT).pl	$(DESTDIR)$(D_BIN)/$(PROJECT)
	install -D -m 0755 src/fwfire.sh			$(DESTDIR)$(D_BIN)/fwfire
	install -D -m 0755 src/fwlog2rule.pl	$(DESTDIR)$(D_BIN)/fwlog2rule
	# install documentation
	for f in $(F_DOCS) ; do \
		install -D -m 0644 $$f $(DESTDIR)$(D_DOC)/$$f || exit 1 ; \
	done
	# ...man pages
	install -Dm0644 man/husk.1.man $(DESTDIR)$(D_MAN)/man1/husk.1p
	install -Dm0644 man/fwfire.1.man $(DESTDIR)$(D_MAN)/man1/fwfire.1p
	install -Dm0644 man/husk.conf.5.man $(DESTDIR)$(D_MAN)/man5/husk.conf.5p
	# ...html docs
	install -Dm0644 man/husk.html $(DESTDIR)$(D_DOC)/husk.html
	install -Dm0644 man/fwfire.html $(DESTDIR)$(D_DOC)/fwfire.html
	install -Dm0644 man/husk.conf.html $(DESTDIR)$(D_DOC)/husk.conf.html
	# ... hook directories
	install -d -m0755 $(DESTDIR)$(D_CNF)/pre.d
	install -d -m0755 $(DESTDIR)$(D_CNF)/post.d

clean:
	rm -f man/*.?.man
	rm -f man/*.html

fallback:
	mkdir $(fb_dir)
	cp $(DESTDIR)$(D_BIN)/$(PROJECT) $(fb_dir)/
	cp $(DESTDIR)$(D_BIN)/fwfire $(fb_dir)/
	cp $(DESTDIR)$(D_BIN)/fwlog2rule.pl $(fb_dir)/
	for f in $(F_DOCS) ; do \
		cp $(DESTDIR)$(D_DOC)/$$f $(fb_dir)/ || exit 1 ; \
	done

	# The next commands could fail if the user hasn't actually created these files
	# so stderr is redirected to /dev/null
	cp $(DESTDIR)$(D_MAN)/man1/husk.1p $(fb_dir)/ 2> /dev/null || true
	cp $(DESTDIR)$(D_MAN)/man1/fwfire.1p $(fb_dir)/ 2> /dev/null || true
	cp $(DESTDIR)$(D_MAN)/man5/husk.conf.5p $(fb_dir)/ 2> /dev/null || true
	cp $(DESTDIR)$(D_CONF)/rules.conf $(fb_dir)/ 2> /dev/null || true
	for f in $(F_CNF) ; do \
		cp $(DESTDIR)$(D_CNF)/$$f $(fb_dir)/ 2> /dev/null || true ; \
	done

	@echo "Fallback has been created in $(fb_dir)"

test:
	@echo "==> Checking for required external dependencies"
	for bindep in $(DEP_BINS) ; do \
		which $$bindep > /dev/null || { echo "$$bindep not found"; exit 1;} ; \
	done

	@echo "==> Checking for required perl modules"
	for pmod in $(DEP_PMODS) ; do \
		perl -M$$pmod -e 1 || { \
			echo '===> Missing Perl Modules detected; Perhaps you need:' ; \
			echo 'RedHat: yum install perl-Config-Simple perl-Config-IniFiles' ; \
			echo 'Debian: apt-get install libconfig-inifiles-perl libconfig-simple-perl' ; \
			exit 1; \
			} ; \
	done

	@echo "==> Checking for valid script syntax"
	@perl -c src/husk.pl
	@perl -c src/fwlog2rule.pl
	@bash -n src/fwfire.sh

	@echo "==> It all looks good Captain!"

bin: test src/$(PROJECT).pl src/fwfire.sh src/fwlog2rule.pl

docs: $(F_DOCS) $(F_MAN)
	# build man pages
	pod2man --name=husk man/husk.pod man/husk.1.man
	pod2man --name=fwfire man/fwfire.pod man/fwfire.1.man
	pod2man --name=fwlog2rule man/fwlog2rule.pod man/fwlog2rule.1.man
	pod2man --name=husk.conf man/husk.conf.pod man/husk.conf.5.man

	# build html pages
	pod2html --infile=man/husk.pod > man/husk.html
	pod2html --infile=man/fwfire.pod > man/fwfire.html
	pod2html --infile=man/fwlog2rule.pod > man/fwlog2rule.html
	pod2html --infile=man/husk.conf.pod > man/husk.conf.html
	rm -f pod2htm*.tmp

config: $(F_CONF)
	# Install Distribution Helper Rule Files
	for f in $(F_HELPERS) ; do \
		install -D -m 0444 helpers/$$f $(DESTDIR)$(D_HELPERS)/$$f || exit 1 ; \
	done
	# Install (without overwriting) configuration files
	for f in $(F_CONF) ; do \
		[ -e $(DESTDIR)$(D_CNF)/$$f ] || \
			install -D -m 0644 $$f $(DESTDIR)$(D_CNF)/$$f ; \
	done

uninstall:
	rm -f $(DESTDIR)$(D_MAN)/man1/husk.1p
	rm -f $(DESTDIR)$(D_MAN)/man1/fwfire.1p
	rm -f $(DESTDIR)$(D_MAN)/man5/husk.conf.5p
	rm -f $(DESTDIR)$(D_BIN)/$(PROJECT)
	rm -f $(DESTDIR)$(D_BIN)/fwfire
	rm -f $(DESTDIR)$(D_BIN)/fwlog2rule
	rm -f $(DESTDIR)$(D_DOC)/*
	rmdir $(DESTDIR)$(D_DOC)/
	@echo "Leaving '$(DESTDIR)$(D_CNF)' untouched"
