lib_LIBRARIES = app_net

AM_CFLAGS := -I$(TOP_LEVEL)/apps/include -I$(TOP_LEVEL)/apps/ipfwd/lib -I$(TOP_LEVEL)/apps/ipfwd/include

app_net_SOURCES := net_dev.c neigh.c ll_cache.c rt.c
app_net_sys_LDADD := pthread
