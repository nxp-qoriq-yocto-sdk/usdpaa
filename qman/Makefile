obj-$(CONFIG_FSL_QMAN)		+= qman_utility.o
obj-$(CONFIG_FSL_QMAN_CONFIG)	+= qman_config.o
obj-$(CONFIG_FSL_QMAN_PORTAL)	+= qman_driver.o qman_low.o qman_high.o
obj-$(CONFIG_FSL_QMAN_FQALLOCATOR) += qman_fqalloc.o
obj-$(CONFIG_FSL_QMAN_TEST)	+= qman_tester.o
qman_tester-y			 = qman_test.o qman_test_hotpotato.o \
				qman_test_high.o qman_test_low.o
qman_tester-$(CONFIG_FSL_QMAN_FQRANGE) += qman_test_fqrange.o
