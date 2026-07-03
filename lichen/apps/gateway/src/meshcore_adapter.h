/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef GATEWAY_MESHCORE_ADAPTER_H_
#define GATEWAY_MESHCORE_ADAPTER_H_

int gateway_meshcore_adapter_init(void);

#ifdef CONFIG_ZTEST
void gateway_meshcore_adapter_test_reset(void);
int gateway_meshcore_adapter_test_reset_status(void);
int gateway_meshcore_adapter_test_process_once(void);
int gateway_meshcore_adapter_test_reload_compat_settings(void);
int gateway_meshcore_adapter_test_corrupt_compat_settings(void);
int gateway_meshcore_adapter_test_write_invalid_compat_settings(void);
#endif

#endif /* GATEWAY_MESHCORE_ADAPTER_H_ */
