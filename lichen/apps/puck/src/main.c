#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(lichen_puck, LOG_LEVEL_INF);

int main(void)
{
	LOG_INF("LICHEN puck starting");
	/* TODO: initialise radio, SCHC, RPL, CoAP */
	return 0;
}
