/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_COAP_WAYPOINTS_H_
#define LICHEN_COAP_WAYPOINTS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <zephyr/net/coap.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LICHEN_WAYPOINT_MAX 8U
#define LICHEN_WAYPOINT_ID_MAX 15U
#define LICHEN_WAYPOINT_NAME_MAX 48U
#define LICHEN_WAYPOINT_CREATOR_MAX 48U
#define LICHEN_WAYPOINT_ICON_MAX 10U
#define LICHEN_WAYPOINT_COLOR_MAX 7U
#define LICHEN_WAYPOINT_NOTES_MAX 96U

struct lichen_waypoint {
  char id[LICHEN_WAYPOINT_ID_MAX + 1U];
  char name[LICHEN_WAYPOINT_NAME_MAX + 1U];
  double lat;
  double lon;
  double alt;
  char creator[LICHEN_WAYPOINT_CREATOR_MAX + 1U];
  char icon[LICHEN_WAYPOINT_ICON_MAX + 1U];
  char color[LICHEN_WAYPOINT_COLOR_MAX + 1U];
  char notes[LICHEN_WAYPOINT_NOTES_MAX + 1U];
  uint64_t created;
  uint64_t expires;
  uint32_t version;
  bool has_alt;
  bool has_icon;
  bool has_color;
  bool has_notes;
  bool has_expires;
};

struct lichen_waypoint_store_image {
  uint32_t format_version;
  uint32_t next_id;
  size_t count;
  struct lichen_waypoint entries[LICHEN_WAYPOINT_MAX];
};

struct lichen_waypoint_config {
  const char *local_creator;
  uint64_t (*now)(void);
  int (*load)(struct lichen_waypoint_store_image *image);
  int (*save)(const struct lichen_waypoint_store_image *image);
};

int lichen_waypoints_init(const struct lichen_waypoint_config *config);
size_t lichen_waypoints_count(void);
int lichen_waypoints_get(size_t index, struct lichen_waypoint *waypoint);
int lichen_waypoints_find(const char *id, struct lichen_waypoint *waypoint);
int lichen_waypoints_create(const struct lichen_waypoint *candidate,
                            struct lichen_waypoint *created);
int lichen_waypoints_update(const char *id,
                            const struct lichen_waypoint *replacement,
                            const char *actor, bool local_admin);
int lichen_waypoints_delete(const char *id, const char *actor,
                            bool local_admin);
int lichen_waypoint_encode(const struct lichen_waypoint *waypoint, uint8_t *buf,
                           size_t buf_size);
int lichen_waypoint_decode(const uint8_t *buf, size_t len,
                           struct lichen_waypoint *waypoint);

int lichen_waypoints_get_handler(struct coap_resource *resource,
                                 struct coap_packet *request,
                                 struct sockaddr *addr, socklen_t addr_len);
int lichen_waypoints_post_handler(struct coap_resource *resource,
                                  struct coap_packet *request,
                                  struct sockaddr *addr, socklen_t addr_len);
int lichen_waypoint_detail_get_handler(struct coap_resource *resource,
                                       struct coap_packet *request,
                                       struct sockaddr *addr,
                                       socklen_t addr_len);
int lichen_waypoint_detail_put_handler(struct coap_resource *resource,
                                       struct coap_packet *request,
                                       struct sockaddr *addr,
                                       socklen_t addr_len);
int lichen_waypoint_detail_delete_handler(struct coap_resource *resource,
                                          struct coap_packet *request,
                                          struct sockaddr *addr,
                                          socklen_t addr_len);

#ifdef __cplusplus
}
#endif

#endif
