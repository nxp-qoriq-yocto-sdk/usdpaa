bin_PROGRAMS = simple_crypto

AM_CFLAGS := -I$(TOP_LEVEL)/apps/include -I$(TOP_LEVEL)/apps/simple_crypto/include

simple_crypto_SOURCES := thread_priv.c simple_crypto.c
simple_crypto_LDADD := usdpaa_qbman usdpaa_dma_mem usdpaa_of usdpaa_sec
simple_crypto_sys_LDADD := pthread
