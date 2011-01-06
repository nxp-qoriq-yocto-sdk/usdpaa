lib_LIBRARIES = app_ip

AM_CFLAGS := -I$(TOP_LEVEL)/apps/ipfwd/include -I$(TOP_LEVEL)/apps/include -I$(TOP_LEVEL)/apps/ipfwd/lib

app_ip_SOURCES := ip_accept.c ip_forward.c ip_handler.c ip_route.c ip_rc.c ip_hooks.c ip_local.c ip_output.c ip_protos.c
app_ip_sys_LDADD := pthread
