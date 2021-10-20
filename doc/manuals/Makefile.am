EXTRA_DIST = \
    osmohnodeb-usermanual.adoc \
    osmohnodeb-usermanual-docinfo.xml \
    osmohnodeb-vty-reference.xml \
    chapters \
    regen_doc.sh \
    vty

if BUILD_MANUALS
  ASCIIDOC = osmohnodeb-usermanual.adoc
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.asciidoc.inc
  osmohnodeb-usermanual.pdf: $(srcdir)/chapters/*.adoc

# TODO: enable once we have VTY available in osmo-hnodeb
#  VTY_REFERENCE = osmohnodeb-vty-reference.xml

#  BUILT_REFERENCE_XML = $(builddir)/vty/hnodeb_vty_reference.xml
#  $(builddir)/vty/hnodeb_vty_reference.xml: $(top_builddir)/src/osmo-hnodeb/osmo-hnodeb
#	mkdir -p $(builddir)/vty
#	$(top_builddir)/src/osmo-hnodeb/osmo-hnodeb --vty-ref-xml > $@

#  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.vty-reference.inc

  OSMO_REPOSITORY = osmo-hnodeb
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.common.inc
endif
