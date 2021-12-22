AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBASN1C_CFLAGS) \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOCTRL_CFLAGS) \
	$(LIBOSMONETIF_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMOTRAU_CFLAGS) \
	$(LIBOSMOSIGTRAN_CFLAGS) \
	$(LIBOSMORUA_CFLAGS) \
	$(LIBOSMORANAP_CFLAGS) \
	$(LIBOSMOHNBAP_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

bin_PROGRAMS = \
	osmo-hnodeb \
	$(NULL)

osmo_hnodeb_SOURCES = \
	main.c \
	debug.c \
	gtp.c \
	hnbap.c \
	hnb.c \
	hnb_shutdown_fsm.c \
	iuh.c \
	llsk.c \
	llsk_audio.c \
	llsk_gtp.c \
	llsk_iuh.c \
	ranap.c \
	rtp.c \
	rua.c \
	vty.c \
	$(NULL)

osmo_hnodeb_LDADD = \
	$(LIBASN1C_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOCTRL_LIBS) \
	$(LIBOSMONETIF_LIBS) \
	$(COVERAGE_LDFLAGS) \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMOTRAU_LIBS) \
	$(LIBOSMOSIGTRAN_LIBS) \
	$(LIBOSMORUA_LIBS) \
	$(LIBOSMORANAP_LIBS) \
	$(LIBOSMOHNBAP_LIBS) \
	$(LIBSCTP_LIBS) \
	$(NULL)
