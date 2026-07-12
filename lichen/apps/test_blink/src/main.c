/* Minimal T1000-E blink: raw NRF registers only, ~1 s on / 1 s off */
#include <zephyr/kernel.h>
#include <nrf52840.h>

int main(void)
{
	NRF_P0->DIRSET = BIT(24);
	while (1) {
		NRF_P0->OUTSET = BIT(24);
		for (volatile uint32_t i = 0; i < 64000000; i++);
		NRF_P0->OUTCLR = BIT(24);
		for (volatile uint32_t i = 0; i < 64000000; i++);
	}
	return 0;
}
