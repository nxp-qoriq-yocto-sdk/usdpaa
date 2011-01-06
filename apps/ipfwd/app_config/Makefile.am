bin_PROGRAMS = ipfwd_config
dist_DATA = ipfwd_22G.script ipfwd_20G_nosgmii_script.sh

AM_CFLAGS := -I$(TOP_LEVEL)/apps/ipfwd/lib -I$(TOP_LEVEL)/apps/ipfwd/include

ipfwd_config_SOURCES := ipc_send.c
ipfwd_config_sys_LDADD := rt
ipfwd_20G_nosgmii_script.sh_install = $(INSTALL_BIN)
ipfwd_20G_nosgmii_script.sh_install_flags = --mode=755
