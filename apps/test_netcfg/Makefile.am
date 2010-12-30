bin_PROGRAMS = test_netcfg
AM_CFLAGS := -I$(TOP_LEVEL)/apps/include

test_netcfg_SOURCES := main.c
test_netcfg_LDADD := netcfg_lib usdpaa_fmc_netcfg usdpaa_qbman usdpaa_fman usdpaa_dma_mem usdpaa_of
test_netcfg_sys_LDADD := xml2
