#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(lichen_gateway, LOG_LEVEL_INF);

int main(void)
{
	LOG_INF("LICHEN gateway starting");
	/* TODO: initialise radio, SCHC, RPL root, SLIP bridge, CoAP proxy */
	return 0;
}
