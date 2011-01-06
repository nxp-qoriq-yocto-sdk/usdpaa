bin_PROGRAMS = ipfwd_app
dist_DATA = config.xml sample-32.xml sample-1024.xml config-20G.xml

AM_CFLAGS := -I$(TOP_LEVEL)/apps/ipfwd/lib -I$(TOP_LEVEL)/apps/include -I$(TOP_LEVEL)/apps/ipfwd/include

ipfwd_app_SOURCES := ipfwd.c ipfwd_handler.c
ipfwd_app_LDADD := usdpaa_qbman usdpaa_fman usdpaa_dma_mem usdpaa_of app_dpa_dev app_ethernet app_ip app_mm app_net apps_arp app_refcount netcfg_lib usdpaa_fmc_netcfg ipfwd_helper
ipfwd_app_sys_LDADD := pthread rt xml2
