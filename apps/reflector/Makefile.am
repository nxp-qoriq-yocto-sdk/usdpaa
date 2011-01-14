bin_PROGRAMS = reflector
dist_DATA = us_config_serdes_0xe.xml us_policy_hash_ipv4_src_dst.xml

AM_CFLAGS := -I$(TOP_LEVEL)/apps/include

reflector_SOURCES := main.c
reflector_LDADD := usdpa_syscfg usdpaa_qbman usdpaa_fman usdpaa_dma_mem usdpaa_of
reflector_sys_LDADD := xml2 z
# Compile in default config paths 
reflector_CFLAGS := -DDEF_PCD_PATH="/$(INSTALL_OTHER)/us_policy_hash_ipv4_src_dst.xml" \
		-DDEF_CFG_PATH="/$(INSTALL_OTHER)/us_config_serdes_0xe.xml"
