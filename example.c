#include <stdio.h>
#include "sldr.h"

void dns_callback (struct sldr_cb_data *cbd) {
	if (cbd->error == SLDR_OK) {
		printf("%s: %u.%u.%u.%u\n", cbd->name,
		       cbd->addr[0], cbd->addr[1], cbd->addr[2], cbd->addr[3]);
	} else {
		printf("Error: %d\n", cbd->error);
	}
}

int main(void)
{
	struct sldr *sldr = sldr_create();
	sldr_queue(sldr, NULL, "google.com", DNS_A_RECORD, dns_callback);
	sldr_poll(sldr, 5 * 1000);	// Resolve, wait no more then 5 sec
	sldr_destroy(&sldr);
	return 0;
}
