SUBDIRS = \
	$(NULL)

# The `:;' works around a Bash 3.2 bug when the output is not writeable.
$(srcdir)/package.m4: $(top_srcdir)/configure.ac
	:;{ \
               echo '# Signature of the current package.' && \
               echo 'm4_define([AT_PACKAGE_NAME],' && \
               echo '  [$(PACKAGE_NAME)])' && \
               echo 'm4_define([AT_PACKAGE_TARNAME],' && \
               echo '  [$(PACKAGE_TARNAME)])' && \
               echo 'm4_define([AT_PACKAGE_VERSION],' && \
               echo '  [$(PACKAGE_VERSION)])' && \
               echo 'm4_define([AT_PACKAGE_STRING],' && \
               echo '  [$(PACKAGE_STRING)])' && \
               echo 'm4_define([AT_PACKAGE_BUGREPORT],' && \
               echo '  [$(PACKAGE_BUGREPORT)])'; \
               echo 'm4_define([AT_PACKAGE_URL],' && \
               echo '  [$(PACKAGE_URL)])'; \
             } >'$(srcdir)/package.m4'

EXTRA_DIST = \
	testsuite.at \
	$(srcdir)/package.m4 \
	$(TESTSUITE) \
	ctrl_test_runner.py \
	osmo-hnodeb.vty \
	$(NULL)

TESTSUITE = $(srcdir)/testsuite

DISTCLEANFILES = \
	atconfig \
	$(NULL)

if ENABLE_EXT_TESTS
python-tests: $(top_builddir)/src/osmo-hnodeb/osmo-hnodeb
	$(MAKE) vty-test
	osmotestvty.py -p $(abs_top_srcdir) -w $(abs_top_builddir) -v
	osmotestconfig.py -p $(abs_top_srcdir) -w $(abs_top_builddir) -v
# TODO: CTRL interface is not implemented
#	$(srcdir)/ctrl_test_runner.py -w $(abs_top_builddir) -v
else
python-tests:
	echo "Not running python-based tests (determined at configure-time)"
endif

# Run a specific test with: 'make vty-test VTY_TEST=osmo-hnodeb.vty'
VTY_TEST ?= *.vty

# To update the VTY script from current application behavior,
# pass -u to vty_script_runner.py by doing:
#   make vty-test U=-u
vty-test: $(top_builddir)/src/osmo-hnodeb/osmo-hnodeb
	osmo_verify_transcript_vty.py -v \
		-n OsmoHNodeB -p 4273 \
		-r "$(top_builddir)/src/osmo-hnodeb/osmo-hnodeb -c $(top_srcdir)/doc/examples/osmo-hnodeb/osmo-hnodeb.cfg" \
		$(U) $(srcdir)/$(VTY_TEST)

check-local: atconfig $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' $(TESTSUITEFLAGS)
	$(MAKE) $(AM_MAKEFLAGS) python-tests

installcheck-local: atconfig $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' AUTOTEST_PATH='$(bindir)' \
		$(TESTSUITEFLAGS)

clean-local:
	test ! -f '$(TESTSUITE)' || \
		$(SHELL) '$(TESTSUITE)' --clean

AUTOM4TE = $(SHELL) $(top_srcdir)/missing --run autom4te
AUTOTEST = $(AUTOM4TE) --language=autotest
$(TESTSUITE): $(srcdir)/testsuite.at $(srcdir)/package.m4
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	mv $@.tmp $@
