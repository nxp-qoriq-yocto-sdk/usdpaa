#include <compat.h>
#include <dma_mem.h>
#include <fman.h>
#include <bigatomic.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <linux/ip.h>
#include <usdpa_netcfg.h>

static void usage(void)
{
	fprintf(stderr, "usage: test_netcfg <fmc_pcd_file> "
					"<fmc_cfgdata_file>\n");
	exit(-1);
}

int main(int argc, char *argv[])
{
	struct usdpa_netcfg_info *uscfg_info;

	printf("---------------START------------------\n");

	if (argc != 3)
		usage();

/*	PCD file = /usr/etc/us_policy_hash_ipv4_src_dst.xml
	CFGDATA file = /usr/etc/us_config_serdes_0xe.xml
*/

	uscfg_info = usdpa_netcfg_acquire(argv[1], argv[2]);
	if (uscfg_info == NULL) {
		fprintf(stderr, "error: NO Config information available\n");
		return -ENXIO;
	}

	dump_usdpa_netcfg(uscfg_info);

	usdpa_netcfg_release(uscfg_info);
	printf("---------------END------------------\n");
	return 0;
}
