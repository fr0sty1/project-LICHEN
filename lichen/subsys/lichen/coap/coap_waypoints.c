/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/coap_waypoints.h>

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/net/net_ip.h>

#include <lichen/coap_oscore.h>
#include <lichen/coap_server.h>

#define WAYPOINT_STORE_FORMAT 1U
#define WAYPOINT_CBOR_MAX 512U
#define WAYPOINT_COLLECTION_CBOR_MAX 1024U
#define WAYPOINT_POST_MAX 512U
#define CBOR_CONTENT_FORMAT 60U

#define FIELD_ID BIT(0)
#define FIELD_NAME BIT(1)
#define FIELD_LAT BIT(2)
#define FIELD_LON BIT(3)
#define FIELD_ALT BIT(4)
#define FIELD_ICON BIT(5)
#define FIELD_COLOR BIT(6)
#define FIELD_NOTES BIT(7)
#define FIELD_CREATED BIT(8)
#define FIELD_CREATOR BIT(9)
#define FIELD_EXPIRES BIT(10)

static struct lichen_waypoint_store_image s_store;
static struct lichen_waypoint_config s_config;
static char s_local_creator[LICHEN_WAYPOINT_CREATOR_MAX + 1U];
static K_MUTEX_DEFINE(s_mutex);
static bool s_initialized;

struct cbor_cursor {
  const uint8_t *buf;
  size_t len;
  size_t off;
};

static bool utf8_valid(const uint8_t *s, size_t len) {
  for (size_t i = 0U; i < len;) {
    uint8_t c = s[i++];
    size_t need;
    uint32_t cp;

    if (c < 0x80U) {
      if (c == 0U) {
        return false;
      }
      continue;
    }
    if (c >= 0xc2U && c <= 0xdfU) {
      need = 1U;
      cp = c & 0x1fU;
    } else if (c >= 0xe0U && c <= 0xefU) {
      need = 2U;
      cp = c & 0x0fU;
    } else if (c >= 0xf0U && c <= 0xf4U) {
      need = 3U;
      cp = c & 0x07U;
    } else {
      return false;
    }
    if (need > len - i) {
      return false;
    }
    for (size_t j = 0U; j < need; j++) {
      uint8_t d = s[i++];

      if ((d & 0xc0U) != 0x80U) {
        return false;
      }
      cp = (cp << 6) | (d & 0x3fU);
    }
    if ((need == 2U && (cp < 0x800U || (cp >= 0xd800U && cp <= 0xdfffU))) ||
        (need == 3U && (cp < 0x10000U || cp > 0x10ffffU))) {
      return false;
    }
  }
  return true;
}

static bool text_valid(const char *s, size_t max, bool allow_empty) {
  size_t len;

  if (s == NULL) {
    return false;
  }
  len = strnlen(s, max + 1U);
  return len <= max && (allow_empty || len > 0U) &&
         utf8_valid((const uint8_t *)s, len);
}

static bool id_valid(const char *id) {
  return text_valid(id, LICHEN_WAYPOINT_ID_MAX, false) && strlen(id) == 7U &&
         memcmp(id, "wpt-", 4U) == 0 && id[4] >= '0' && id[4] <= '9' &&
         id[5] >= '0' && id[5] <= '9' && id[6] >= '0' && id[6] <= '9' &&
         (id[4] != '0' || id[5] != '0' || id[6] != '0');
}

static bool icon_valid(const char *icon) {
  static const char *const allowed[] = {
      "flag",    "marker", "camp",  "water",  "danger",     "medical",
      "vehicle", "poi",    "start", "finish", "checkpoint",
  };

  for (size_t i = 0U; i < ARRAY_SIZE(allowed); i++) {
    if (strcmp(icon, allowed[i]) == 0) {
      return true;
    }
  }
  return false;
}

static bool color_valid(const char *color) {
  if (strlen(color) != 7U || color[0] != '#') {
    return false;
  }
  for (size_t i = 1U; i < 7U; i++) {
    char c = color[i];

    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
          (c >= 'A' && c <= 'F'))) {
      return false;
    }
  }
  return true;
}

static int waypoint_validate(const struct lichen_waypoint *w, bool full) {
  if (w == NULL || (full && !id_valid(w->id)) ||
      !text_valid(w->name, LICHEN_WAYPOINT_NAME_MAX, false) ||
      !isfinite(w->lat) || w->lat < -90.0 || w->lat > 90.0 ||
      !isfinite(w->lon) || w->lon < -180.0 || w->lon > 180.0 ||
      (w->has_alt &&
       (!isfinite(w->alt) || w->alt < -12000.0 || w->alt > 100000.0)) ||
      (w->has_icon && (!text_valid(w->icon, LICHEN_WAYPOINT_ICON_MAX, false) ||
                       !icon_valid(w->icon))) ||
      (w->has_color &&
       (!text_valid(w->color, LICHEN_WAYPOINT_COLOR_MAX, false) ||
        !color_valid(w->color))) ||
      (w->has_notes &&
       !text_valid(w->notes, LICHEN_WAYPOINT_NOTES_MAX, false)) ||
      (full && !text_valid(w->creator, LICHEN_WAYPOINT_CREATOR_MAX, false)) ||
      (w->has_expires && w->created != 0U && w->expires != 0U &&
       w->expires <= w->created)) {
    return -EINVAL;
  }
  return 0;
}

static int image_validate(const struct lichen_waypoint_store_image *image) {
  if (image->format_version != WAYPOINT_STORE_FORMAT || image->next_id == 0U ||
      image->count > LICHEN_WAYPOINT_MAX) {
    return -EBADMSG;
  }
  for (size_t i = 0U; i < image->count; i++) {
    if (waypoint_validate(&image->entries[i], true) < 0 ||
        image->entries[i].version == 0U) {
      return -EBADMSG;
    }
    for (size_t j = i + 1U; j < image->count; j++) {
      if (strcmp(image->entries[i].id, image->entries[j].id) == 0) {
        return -EBADMSG;
      }
    }
  }
  return 0;
}

static int persist(const struct lichen_waypoint_store_image *image) {
  int ret = s_config.save == NULL ? 0 : s_config.save(image);

  return ret <= 0 ? ret : -EIO;
}

int lichen_waypoints_init(const struct lichen_waypoint_config *config) {
  struct lichen_waypoint_store_image image = {
      .format_version = WAYPOINT_STORE_FORMAT,
      .next_id = 1U,
  };
  int ret;

  if (config == NULL ||
      !text_valid(config->local_creator, LICHEN_WAYPOINT_CREATOR_MAX, false)) {
    return -EINVAL;
  }
  if (config->load != NULL) {
    ret = config->load(&image);
    if (ret > 0) {
      return -EIO;
    }
    if (ret < 0 && ret != -ENOENT) {
      return ret;
    }
    if (ret == 0 && image_validate(&image) < 0) {
      return -EBADMSG;
    }
    if (ret == -ENOENT) {
      memset(&image, 0, sizeof(image));
      image.format_version = WAYPOINT_STORE_FORMAT;
      image.next_id = 1U;
    }
  }
  k_mutex_lock(&s_mutex, K_FOREVER);
  s_config = *config;
  strncpy(s_local_creator, config->local_creator, sizeof(s_local_creator) - 1U);
  s_local_creator[sizeof(s_local_creator) - 1U] = '\0';
  s_config.local_creator = s_local_creator;
  s_store = image;
  s_initialized = true;
  k_mutex_unlock(&s_mutex);
  return 0;
}

size_t lichen_waypoints_count(void) {
  size_t count;

  k_mutex_lock(&s_mutex, K_FOREVER);
  count = s_initialized ? s_store.count : 0U;
  k_mutex_unlock(&s_mutex);
  return count;
}

int lichen_waypoints_get(size_t index, struct lichen_waypoint *waypoint) {
  int ret = -ENOENT;

  if (waypoint == NULL) {
    return -EINVAL;
  }
  k_mutex_lock(&s_mutex, K_FOREVER);
  if (!s_initialized) {
    ret = -ENODEV;
  } else if (index < s_store.count) {
    *waypoint = s_store.entries[index];
    ret = 0;
  }
  k_mutex_unlock(&s_mutex);
  return ret;
}

int lichen_waypoints_find(const char *id, struct lichen_waypoint *waypoint) {
  int ret = -ENOENT;

  if (!id_valid(id) || waypoint == NULL) {
    return -EINVAL;
  }
  k_mutex_lock(&s_mutex, K_FOREVER);
  if (!s_initialized) {
    ret = -ENODEV;
  } else {
    for (size_t i = 0U; i < s_store.count; i++) {
      if (strcmp(s_store.entries[i].id, id) == 0) {
        *waypoint = s_store.entries[i];
        ret = 0;
        break;
      }
    }
  }
  k_mutex_unlock(&s_mutex);
  return ret;
}

static bool actor_can_mutate(const struct lichen_waypoint *waypoint,
                             const char *actor, bool local_admin) {
  return local_admin ||
         (actor != NULL && strcmp(actor, waypoint->creator) == 0);
}

int lichen_waypoints_create(const struct lichen_waypoint *candidate,
                            struct lichen_waypoint *created) {
  struct lichen_waypoint_store_image staged;
  struct lichen_waypoint value;
  int ret;

  if (candidate == NULL || created == NULL ||
      waypoint_validate(candidate, false) < 0) {
    return -EINVAL;
  }
  value = *candidate;
  k_mutex_lock(&s_mutex, K_FOREVER);
  if (!s_initialized) {
    ret = -ENODEV;
    goto out;
  }
  if (s_store.count >= LICHEN_WAYPOINT_MAX) {
    ret = -ENOSPC;
    goto out;
  }
  staged = s_store;
  if (value.id[0] == '\0') {
    if (staged.next_id > 999U) {
      ret = -EOVERFLOW;
      goto out;
    }
    int written =
        snprintf(value.id, sizeof(value.id), "wpt-%03u", staged.next_id);

    if (written < 0 || (size_t)written >= sizeof(value.id)) {
      ret = -EOVERFLOW;
      goto out;
    }
    staged.next_id++;
    if (staged.next_id == 0U) {
      ret = -EOVERFLOW;
      goto out;
    }
  } else if (!id_valid(value.id)) {
    ret = -EINVAL;
    goto out;
  }
  for (size_t i = 0U; i < staged.count; i++) {
    if (strcmp(staged.entries[i].id, value.id) == 0) {
      ret = -EEXIST;
      goto out;
    }
  }
  if (value.creator[0] == '\0') {
    strncpy(value.creator, s_config.local_creator, sizeof(value.creator) - 1U);
    value.creator[sizeof(value.creator) - 1U] = '\0';
  }
  if (value.created == 0U && s_config.now != NULL) {
    value.created = s_config.now();
  }
  value.version = 1U;
  if (waypoint_validate(&value, true) < 0) {
    ret = -EINVAL;
    goto out;
  }
  staged.entries[staged.count++] = value;
  ret = persist(&staged);
  if (ret < 0) {
    goto out;
  }
  s_store = staged;
  *created = value;
  ret = 0;
out:
  k_mutex_unlock(&s_mutex);
  return ret;
}

int lichen_waypoints_update(const char *id,
                            const struct lichen_waypoint *replacement,
                            const char *actor, bool local_admin) {
  struct lichen_waypoint_store_image staged;
  struct lichen_waypoint value;
  int ret = -ENOENT;

  if (!id_valid(id) || replacement == NULL) {
    return -EINVAL;
  }
  k_mutex_lock(&s_mutex, K_FOREVER);
  if (!s_initialized) {
    ret = -ENODEV;
    goto out;
  }
  staged = s_store;
  for (size_t i = 0U; i < staged.count; i++) {
    if (strcmp(staged.entries[i].id, id) != 0) {
      continue;
    }
    if (!actor_can_mutate(&staged.entries[i], actor, local_admin)) {
      ret = -EACCES;
      goto out;
    }
    value = *replacement;
    strncpy(value.id, staged.entries[i].id, sizeof(value.id) - 1U);
    value.id[sizeof(value.id) - 1U] = '\0';
    strncpy(value.creator, staged.entries[i].creator,
            sizeof(value.creator) - 1U);
    value.creator[sizeof(value.creator) - 1U] = '\0';
    value.created = staged.entries[i].created;
    value.version = staged.entries[i].version + 1U;
    if (value.version == 0U || waypoint_validate(&value, true) < 0) {
      ret = -EINVAL;
      goto out;
    }
    staged.entries[i] = value;
    ret = persist(&staged);
    if (ret == 0) {
      s_store = staged;
    }
    goto out;
  }
out:
  k_mutex_unlock(&s_mutex);
  return ret;
}

int lichen_waypoints_delete(const char *id, const char *actor,
                            bool local_admin) {
  struct lichen_waypoint_store_image staged;
  int ret = -ENOENT;

  if (!id_valid(id)) {
    return -EINVAL;
  }
  k_mutex_lock(&s_mutex, K_FOREVER);
  if (!s_initialized) {
    ret = -ENODEV;
    goto out;
  }
  staged = s_store;
  for (size_t i = 0U; i < staged.count; i++) {
    if (strcmp(staged.entries[i].id, id) != 0) {
      continue;
    }
    if (!actor_can_mutate(&staged.entries[i], actor, local_admin)) {
      ret = -EACCES;
      goto out;
    }
    memmove(&staged.entries[i], &staged.entries[i + 1U],
            (staged.count - i - 1U) * sizeof(staged.entries[0]));
    staged.count--;
    memset(&staged.entries[staged.count], 0, sizeof(staged.entries[0]));
    ret = persist(&staged);
    if (ret == 0) {
      s_store = staged;
    }
    goto out;
  }
out:
  k_mutex_unlock(&s_mutex);
  return ret;
}

struct cbor_writer {
  uint8_t *buf;
  size_t size;
  size_t off;
  bool failed;
};

static void put_bytes(struct cbor_writer *w, const void *data, size_t len) {
  if (w->failed || len > w->size - w->off) {
    w->failed = true;
    return;
  }
  memcpy(&w->buf[w->off], data, len);
  w->off += len;
}

static void put_head(struct cbor_writer *w, uint8_t major, uint64_t value) {
  uint8_t bytes[9];
  size_t len;

  if (value < 24U) {
    bytes[0] = (uint8_t)((major << 5) | value);
    len = 1U;
  } else if (value <= UINT8_MAX) {
    bytes[0] = (uint8_t)((major << 5) | 24U);
    bytes[1] = (uint8_t)value;
    len = 2U;
  } else if (value <= UINT16_MAX) {
    bytes[0] = (uint8_t)((major << 5) | 25U);
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)value;
    len = 3U;
  } else if (value <= UINT32_MAX) {
    bytes[0] = (uint8_t)((major << 5) | 26U);
    for (size_t i = 0U; i < 4U; i++) {
      bytes[1U + i] = (uint8_t)(value >> (24U - 8U * i));
    }
    len = 5U;
  } else {
    bytes[0] = (uint8_t)((major << 5) | 27U);
    for (size_t i = 0U; i < 8U; i++) {
      bytes[1U + i] = (uint8_t)(value >> (56U - 8U * i));
    }
    len = 9U;
  }
  put_bytes(w, bytes, len);
}

static void put_text(struct cbor_writer *w, const char *value) {
  size_t len = strlen(value);

  put_head(w, 3U, len);
  put_bytes(w, value, len);
}

static void put_double(struct cbor_writer *w, double value) {
  uint64_t bits;
  uint8_t bytes[9] = {0xfbU};

  memcpy(&bits, &value, sizeof(bits));
  for (size_t i = 0U; i < 8U; i++) {
    bytes[1U + i] = (uint8_t)(bits >> (56U - 8U * i));
  }
  put_bytes(w, bytes, sizeof(bytes));
}

static void encode_waypoint(struct cbor_writer *w,
                            const struct lichen_waypoint *waypoint) {
  size_t fields = 6U + waypoint->has_alt + waypoint->has_icon +
                  waypoint->has_color + waypoint->has_notes +
                  waypoint->has_expires;

  put_head(w, 5U, fields);
  put_text(w, "id");
  put_text(w, waypoint->id);
  put_text(w, "name");
  put_text(w, waypoint->name);
  put_text(w, "lat");
  put_double(w, waypoint->lat);
  put_text(w, "lon");
  put_double(w, waypoint->lon);
  if (waypoint->has_alt) {
    put_text(w, "alt");
    put_double(w, waypoint->alt);
  }
  if (waypoint->has_icon) {
    put_text(w, "icon");
    put_text(w, waypoint->icon);
  }
  if (waypoint->has_color) {
    put_text(w, "color");
    put_text(w, waypoint->color);
  }
  if (waypoint->has_notes) {
    put_text(w, "notes");
    put_text(w, waypoint->notes);
  }
  put_text(w, "created");
  put_head(w, 0U, waypoint->created);
  put_text(w, "creator");
  put_text(w, waypoint->creator);
  if (waypoint->has_expires) {
    put_text(w, "expires");
    put_head(w, 0U, waypoint->expires);
  }
}

int lichen_waypoint_encode(const struct lichen_waypoint *waypoint, uint8_t *buf,
                           size_t buf_size) {
  uint8_t encoded[WAYPOINT_CBOR_MAX];
  struct cbor_writer writer = {.buf = encoded, .size = sizeof(encoded)};

  if (buf == NULL || waypoint_validate(waypoint, true) < 0) {
    return -EINVAL;
  }
  encode_waypoint(&writer, waypoint);
  if (writer.failed || writer.off > buf_size) {
    return -ENOBUFS;
  }
  memcpy(buf, encoded, writer.off);
  return (int)writer.off;
}

static bool read_bytes(struct cbor_cursor *c, void *dst, size_t len) {
  if (len > c->len - c->off) {
    return false;
  }
  if (dst != NULL) {
    memcpy(dst, &c->buf[c->off], len);
  }
  c->off += len;
  return true;
}

static bool read_head(struct cbor_cursor *c, uint8_t *major, uint64_t *value) {
  uint8_t first;
  uint8_t ai;
  uint64_t decoded = 0U;
  size_t width;

  if (!read_bytes(c, &first, 1U)) {
    return false;
  }
  *major = first >> 5;
  ai = first & 0x1fU;
  if (ai < 24U) {
    *value = ai;
    return true;
  }
  if (ai == 24U) {
    width = 1U;
  } else if (ai == 25U) {
    width = 2U;
  } else if (ai == 26U) {
    width = 4U;
  } else if (ai == 27U) {
    width = 8U;
  } else {
    return false;
  }
  if (width > c->len - c->off) {
    return false;
  }
  for (size_t i = 0U; i < width; i++) {
    decoded = (decoded << 8) | c->buf[c->off++];
  }
  if ((width == 1U && decoded < 24U) || (width == 2U && decoded <= UINT8_MAX) ||
      (width == 4U && decoded <= UINT16_MAX) ||
      (width == 8U && decoded <= UINT32_MAX)) {
    return false;
  }
  *value = decoded;
  return true;
}

static bool read_text(struct cbor_cursor *c, char *dst, size_t max) {
  uint8_t major;
  uint64_t len;

  if (!read_head(c, &major, &len) || major != 3U || len > max ||
      len > c->len - c->off || !utf8_valid(&c->buf[c->off], (size_t)len)) {
    return false;
  }
  memcpy(dst, &c->buf[c->off], (size_t)len);
  dst[len] = '\0';
  c->off += (size_t)len;
  return true;
}

static bool read_uint(struct cbor_cursor *c, uint64_t *value) {
  uint8_t major;

  return read_head(c, &major, value) && major == 0U;
}

static bool read_double(struct cbor_cursor *c, double *value) {
  uint64_t bits = 0U;
  uint8_t marker;

  /* The shared waypoint corpus deliberately requires binary64 coordinates.
   * Reject narrower, tagged and non-canonical representations. */
  if (!read_bytes(c, &marker, 1U) || marker != 0xfbU ||
      c->len - c->off < sizeof(bits)) {
    return false;
  }
  for (size_t i = 0U; i < sizeof(bits); i++) {
    bits = (bits << 8) | c->buf[c->off++];
  }
  memcpy(value, &bits, sizeof(bits));
  return isfinite(*value);
}

static int decode_waypoint(const uint8_t *buf, size_t len,
                           struct lichen_waypoint *waypoint, bool full) {
  struct cbor_cursor cursor = {.buf = buf, .len = len};
  struct lichen_waypoint decoded = {0};
  uint32_t fields = 0U;
  uint8_t major;
  uint64_t pairs;

  if (buf == NULL || waypoint == NULL || !read_head(&cursor, &major, &pairs) ||
      major != 5U || pairs > 11U) {
    return -EBADMSG;
  }
  for (uint64_t i = 0U; i < pairs; i++) {
    char key[9];
    uint32_t bit;
    bool ok;

    if (!read_text(&cursor, key, sizeof(key) - 1U)) {
      return -EBADMSG;
    }
    if (strcmp(key, "id") == 0) {
      bit = FIELD_ID;
      ok = read_text(&cursor, decoded.id, LICHEN_WAYPOINT_ID_MAX);
    } else if (strcmp(key, "name") == 0) {
      bit = FIELD_NAME;
      ok = read_text(&cursor, decoded.name, LICHEN_WAYPOINT_NAME_MAX);
    } else if (strcmp(key, "lat") == 0) {
      bit = FIELD_LAT;
      ok = read_double(&cursor, &decoded.lat);
    } else if (strcmp(key, "lon") == 0) {
      bit = FIELD_LON;
      ok = read_double(&cursor, &decoded.lon);
    } else if (strcmp(key, "alt") == 0) {
      bit = FIELD_ALT;
      ok = read_double(&cursor, &decoded.alt);
    } else if (strcmp(key, "icon") == 0) {
      bit = FIELD_ICON;
      ok = read_text(&cursor, decoded.icon, LICHEN_WAYPOINT_ICON_MAX);
    } else if (strcmp(key, "color") == 0) {
      bit = FIELD_COLOR;
      ok = read_text(&cursor, decoded.color, LICHEN_WAYPOINT_COLOR_MAX);
    } else if (strcmp(key, "notes") == 0) {
      bit = FIELD_NOTES;
      ok = read_text(&cursor, decoded.notes, LICHEN_WAYPOINT_NOTES_MAX);
    } else if (strcmp(key, "created") == 0) {
      bit = FIELD_CREATED;
      ok = read_uint(&cursor, &decoded.created);
    } else if (strcmp(key, "creator") == 0) {
      bit = FIELD_CREATOR;
      ok = read_text(&cursor, decoded.creator, LICHEN_WAYPOINT_CREATOR_MAX);
    } else if (strcmp(key, "expires") == 0) {
      bit = FIELD_EXPIRES;
      ok = read_uint(&cursor, &decoded.expires);
    } else {
      return -EBADMSG;
    }
    if ((fields & bit) != 0U || !ok) {
      return -EBADMSG;
    }
    fields |= bit;
  }
  if (cursor.off != cursor.len ||
      (fields & (FIELD_NAME | FIELD_LAT | FIELD_LON)) !=
          (FIELD_NAME | FIELD_LAT | FIELD_LON) ||
      (full && (fields & (FIELD_ID | FIELD_CREATED | FIELD_CREATOR)) !=
                   (FIELD_ID | FIELD_CREATED | FIELD_CREATOR))) {
    return -EBADMSG;
  }
  decoded.has_alt = (fields & FIELD_ALT) != 0U;
  decoded.has_icon = (fields & FIELD_ICON) != 0U;
  decoded.has_color = (fields & FIELD_COLOR) != 0U;
  decoded.has_notes = (fields & FIELD_NOTES) != 0U;
  decoded.has_expires = (fields & FIELD_EXPIRES) != 0U;
  decoded.version = 1U;
  if (waypoint_validate(&decoded, full) < 0 ||
      ((fields & FIELD_ID) != 0U && !id_valid(decoded.id)) ||
      ((fields & FIELD_CREATOR) != 0U &&
       !text_valid(decoded.creator, LICHEN_WAYPOINT_CREATOR_MAX, false))) {
    return -EBADMSG;
  }
  *waypoint = decoded;
  return 0;
}

int lichen_waypoint_decode(const uint8_t *buf, size_t len,
                           struct lichen_waypoint *waypoint) {
  return decode_waypoint(buf, len, waypoint, true);
}

static int parse_pagination(const struct coap_packet *request, size_t *offset,
                            size_t *limit) {
  struct coap_option options[3];
  unsigned int seen = 0U;
  int count;

  *offset = 0U;
  *limit = LICHEN_WAYPOINT_MAX;
  count = coap_find_options(request, COAP_OPTION_URI_QUERY, options,
                            ARRAY_SIZE(options));
  if (count < 0 || count > 2) {
    return -EBADMSG;
  }
  for (int i = 0; i < count; i++) {
    const uint8_t *value = options[i].value;
    size_t len = options[i].len;
    size_t prefix;
    unsigned int bit;

    if (len == 8U && memcmp(value, "offset=", 7U) == 0) {
      prefix = 7U;
      bit = BIT(0);
    } else if (len == 7U && memcmp(value, "limit=", 6U) == 0) {
      prefix = 6U;
      bit = BIT(1);
    } else {
      return -EBADMSG;
    }
    if ((seen & bit) != 0U || value[prefix] < '0' || value[prefix] > '8' ||
        (bit == BIT(1) && value[prefix] == '0')) {
      return -EBADMSG;
    }
    seen |= bit;
    if (bit == BIT(0)) {
      *offset = value[prefix] - '0';
    } else {
      *limit = value[prefix] - '0';
    }
  }
  return 0;
}

static int encode_collection(size_t offset, size_t limit, uint8_t *buf,
                             size_t size) {
  uint8_t entries[WAYPOINT_COLLECTION_CBOR_MAX];
  struct cbor_writer ew = {
      .buf = entries,
      .size = MIN(sizeof(entries), size > 32U ? size - 32U : 0U),
  };
  struct cbor_writer out = {.buf = buf, .size = size};
  size_t selected = 0U;
  size_t count;

  k_mutex_lock(&s_mutex, K_FOREVER);
  if (!s_initialized) {
    k_mutex_unlock(&s_mutex);
    return -ENODEV;
  }
  count = s_store.count;
  for (size_t i = offset; i < count && selected < limit; i++) {
    size_t before = ew.off;

    encode_waypoint(&ew, &s_store.entries[i]);
    if (ew.failed) {
      ew.failed = false;
      ew.off = before;
      break;
    }
    selected++;
  }
  k_mutex_unlock(&s_mutex);
  if (offset < count && selected == 0U) {
    return -ENOBUFS;
  }
  put_head(&out, 5U, 1U);
  put_text(&out, "waypoints");
  put_head(&out, 4U, selected);
  put_bytes(&out, entries, ew.off);
  return out.failed ? -ENOBUFS : (int)out.off;
}

int lichen_waypoints_get_handler(struct coap_resource *resource,
                                 struct coap_packet *request,
                                 struct sockaddr *addr, socklen_t addr_len) {
  uint8_t payload[WAYPOINT_COLLECTION_CBOR_MAX];
  size_t offset;
  size_t limit;
  int len;

  if (parse_pagination(request, &offset, &limit) < 0) {
    return lichen_coap_respond(resource, request, addr, addr_len,
                               COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
  }
  len = encode_collection(offset, limit, payload, sizeof(payload));
  if (len < 0) {
    return lichen_coap_respond(resource, request, addr, addr_len,
                               COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
  }
  return lichen_coap_respond(resource, request, addr, addr_len,
                             COAP_RESPONSE_CODE_CONTENT, CBOR_CONTENT_FORMAT,
                             payload, (size_t)len);
}

static int request_actor(const struct sockaddr *addr, socklen_t addr_len,
                         char actor[LICHEN_WAYPOINT_CREATOR_MAX + 1U],
                         bool *local_admin) {
  *local_admin = lichen_coap_is_local_admin(addr, addr_len);
  if (*local_admin) {
    k_mutex_lock(&s_mutex, K_FOREVER);
    if (!s_initialized) {
      k_mutex_unlock(&s_mutex);
      return -ENODEV;
    }
    strncpy(actor, s_config.local_creator, LICHEN_WAYPOINT_CREATOR_MAX);
    actor[LICHEN_WAYPOINT_CREATOR_MAX] = '\0';
    k_mutex_unlock(&s_mutex);
    return 0;
  }
  if (addr == NULL || addr_len < sizeof(struct sockaddr_in6) ||
      addr->sa_family != AF_INET6 ||
      net_addr_ntop(AF_INET6, &((const struct sockaddr_in6 *)addr)->sin6_addr,
                    actor, LICHEN_WAYPOINT_CREATOR_MAX + 1U) == NULL) {
    return -EACCES;
  }
  return 0;
}

static bool creator_matches_peer(const char *creator,
                                 const struct sockaddr *addr,
                                 socklen_t addr_len) {
  struct in6_addr claimed;

  return creator != NULL && addr != NULL &&
         addr_len >= sizeof(struct sockaddr_in6) &&
         addr->sa_family == AF_INET6 &&
         net_addr_pton(AF_INET6, creator, &claimed) == 0 &&
         memcmp(&claimed, &((const struct sockaddr_in6 *)addr)->sin6_addr,
                sizeof(claimed)) == 0;
}

static int send_created(struct coap_resource *resource,
                        struct coap_packet *request, struct sockaddr *addr,
                        socklen_t addr_len,
                        const struct coap_oscore_unprotect_result *oscore,
                        const char *id) {
  uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
  struct coap_packet response;
  int ret;

#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
  if (oscore->is_protected && oscore->ctx != NULL && oscore->piv_len > 0U) {
    ret = coap_oscore_protect_response(
        oscore->ctx, oscore->piv, oscore->piv_len, request,
        COAP_RESPONSE_CODE_CREATED, NULL, 0U, &response, buf, sizeof(buf));
  } else
#endif
  {
    uint8_t token[COAP_TOKEN_MAX_LEN];
    uint8_t token_len = coap_header_get_token(request, token);
    uint8_t type = coap_header_get_type(request) == COAP_TYPE_CON
                       ? COAP_TYPE_ACK
                       : COAP_TYPE_NON_CON;

    ret = coap_packet_init(&response, buf, sizeof(buf), COAP_VERSION_1, type,
                           token_len, token, COAP_RESPONSE_CODE_CREATED,
                           coap_header_get_id(request));
  }
  if (ret < 0) {
    return ret;
  }
  ret = coap_packet_append_option(&response, COAP_OPTION_LOCATION_PATH,
                                  "waypoints", 9U);
  if (ret == 0) {
    ret = coap_packet_append_option(&response, COAP_OPTION_LOCATION_PATH, id,
                                    strlen(id));
  }
  return ret < 0
             ? ret
             : coap_resource_send(resource, &response, addr, addr_len, NULL);
}

int lichen_waypoints_post_handler(struct coap_resource *resource,
                                  struct coap_packet *request,
                                  struct sockaddr *addr, socklen_t addr_len) {
  struct coap_oscore_unprotect_result oscore;
  struct lichen_waypoint candidate;
  struct lichen_waypoint created;
  char actor[LICHEN_WAYPOINT_CREATOR_MAX + 1U] = {0};
  bool local_admin;
  int ret;

  ret = coap_oscore_unprotect_resource_request(
      resource, request, addr, addr_len, COAP_METHOD_POST, &oscore);
  if (ret != 0) {
    return ret;
  }
  ret = request_actor(addr, addr_len, actor, &local_admin);
  if (ret < 0 || (!local_admin && !oscore.is_protected)) {
    return coap_oscore_respond_resource(
        resource, request, addr, addr_len, &oscore,
        COAP_RESPONSE_CODE_UNAUTHORIZED, 0, NULL, 0);
  }
  if (!oscore.is_protected) {
    int content_format =
        coap_get_option_int(request, COAP_OPTION_CONTENT_FORMAT);

    if (content_format != -ENOENT && content_format != CBOR_CONTENT_FORMAT) {
      return coap_oscore_respond_resource(
          resource, request, addr, addr_len, &oscore,
          COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
    }
  }
  if (oscore.payload == NULL || oscore.payload_len == 0U) {
    return coap_oscore_respond_resource(resource, request, addr, addr_len,
                                        &oscore, COAP_RESPONSE_CODE_BAD_REQUEST,
                                        0, NULL, 0);
  }
  if (oscore.payload_len > WAYPOINT_POST_MAX) {
    return coap_oscore_respond_resource(
        resource, request, addr, addr_len, &oscore,
        COAP_RESPONSE_CODE_REQUEST_TOO_LARGE, 0, NULL, 0);
  }
  if (decode_waypoint(oscore.payload, oscore.payload_len, &candidate, false) <
      0) {
    return coap_oscore_respond_resource(resource, request, addr, addr_len,
                                        &oscore, COAP_RESPONSE_CODE_BAD_REQUEST,
                                        0, NULL, 0);
  }
  if (candidate.creator[0] != '\0' && !local_admin &&
      !creator_matches_peer(candidate.creator, addr, addr_len)) {
    return coap_oscore_respond_resource(resource, request, addr, addr_len,
                                        &oscore, COAP_RESPONSE_CODE_FORBIDDEN,
                                        0, NULL, 0);
  }
  if (candidate.creator[0] == '\0') {
    strncpy(candidate.creator, actor, sizeof(candidate.creator) - 1U);
  }
  ret = lichen_waypoints_create(&candidate, &created);
  if (ret == -EEXIST) {
    return coap_oscore_respond_resource(resource, request, addr, addr_len,
                                        &oscore, COAP_RESPONSE_CODE_CONFLICT, 0,
                                        NULL, 0);
  }
  if (ret == -EINVAL) {
    return coap_oscore_respond_resource(resource, request, addr, addr_len,
                                        &oscore, COAP_RESPONSE_CODE_BAD_REQUEST,
                                        0, NULL, 0);
  }
  if (ret < 0) {
    return coap_oscore_respond_resource(
        resource, request, addr, addr_len, &oscore,
        COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE, 0, NULL, 0);
  }
  return send_created(resource, request, addr, addr_len, &oscore, created.id);
}

static int extract_detail_id(const struct coap_packet *request,
                             char id[LICHEN_WAYPOINT_ID_MAX + 1U]) {
  struct coap_option paths[3];
  int count = coap_find_options(request, COAP_OPTION_URI_PATH, paths,
                                ARRAY_SIZE(paths));

  if (count != 2 || paths[0].len != 9U ||
      memcmp(paths[0].value, "waypoints", 9U) != 0 || paths[1].len != 7U) {
    return -ENOENT;
  }
  memcpy(id, paths[1].value, paths[1].len);
  id[paths[1].len] = '\0';
  return id_valid(id) ? 0 : -ENOENT;
}

int lichen_waypoint_detail_get_handler(struct coap_resource *resource,
                                       struct coap_packet *request,
                                       struct sockaddr *addr,
                                       socklen_t addr_len) {
  struct coap_oscore_unprotect_result oscore;
  struct lichen_waypoint waypoint;
  uint8_t payload[WAYPOINT_CBOR_MAX];
  char id[LICHEN_WAYPOINT_ID_MAX + 1U];
  int ret;

  ret = coap_oscore_unprotect_resource_request(
      resource, request, addr, addr_len, COAP_METHOD_GET, &oscore);
  if (ret != 0) {
    return ret;
  }
  if (oscore.payload_len != 0U) {
    return coap_oscore_respond_resource(resource, request, addr, addr_len,
                                        &oscore, COAP_RESPONSE_CODE_BAD_REQUEST,
                                        0, NULL, 0);
  }
  if (extract_detail_id(request, id) < 0 ||
      lichen_waypoints_find(id, &waypoint) < 0) {
    return coap_oscore_respond_resource(resource, request, addr, addr_len,
                                        &oscore, COAP_RESPONSE_CODE_NOT_FOUND,
                                        0, NULL, 0);
  }
  ret = lichen_waypoint_encode(&waypoint, payload, sizeof(payload));
  if (ret < 0) {
    return coap_oscore_respond_resource(
        resource, request, addr, addr_len, &oscore,
        COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
  }
  return coap_oscore_respond_resource(
      resource, request, addr, addr_len, &oscore, COAP_RESPONSE_CODE_CONTENT,
      CBOR_CONTENT_FORMAT, payload, (size_t)ret);
}

int lichen_waypoint_detail_put_handler(struct coap_resource *resource,
                                       struct coap_packet *request,
                                       struct sockaddr *addr,
                                       socklen_t addr_len) {
  struct coap_oscore_unprotect_result oscore;
  int ret = coap_oscore_unprotect_resource_request(
      resource, request, addr, addr_len, COAP_METHOD_PUT, &oscore);

  if (ret != 0) {
    return ret;
  }
  return coap_oscore_respond_resource(resource, request, addr, addr_len,
                                      &oscore, COAP_RESPONSE_CODE_NOT_ALLOWED,
                                      0, NULL, 0);
}

int lichen_waypoint_detail_delete_handler(struct coap_resource *resource,
                                          struct coap_packet *request,
                                          struct sockaddr *addr,
                                          socklen_t addr_len) {
  struct coap_oscore_unprotect_result oscore;
  char actor[LICHEN_WAYPOINT_CREATOR_MAX + 1U] = {0};
  char id[LICHEN_WAYPOINT_ID_MAX + 1U];
  bool local_admin;
  int ret;

  ret = coap_oscore_unprotect_resource_request(
      resource, request, addr, addr_len, COAP_METHOD_DELETE, &oscore);
  if (ret != 0) {
    return ret;
  }
  if (oscore.payload_len != 0U) {
    return coap_oscore_respond_resource(resource, request, addr, addr_len,
                                        &oscore, COAP_RESPONSE_CODE_BAD_REQUEST,
                                        0, NULL, 0);
  }
  if (extract_detail_id(request, id) < 0) {
    return coap_oscore_respond_resource(resource, request, addr, addr_len,
                                        &oscore, COAP_RESPONSE_CODE_NOT_FOUND,
                                        0, NULL, 0);
  }
  ret = request_actor(addr, addr_len, actor, &local_admin);
  if (ret < 0 || (!local_admin && !oscore.is_protected)) {
    return coap_oscore_respond_resource(
        resource, request, addr, addr_len, &oscore,
        COAP_RESPONSE_CODE_UNAUTHORIZED, 0, NULL, 0);
  }
  ret = lichen_waypoints_delete(id, actor, local_admin);
  if (ret == -ENOENT) {
    return coap_oscore_respond_resource(resource, request, addr, addr_len,
                                        &oscore, COAP_RESPONSE_CODE_NOT_FOUND,
                                        0, NULL, 0);
  }
  if (ret == -EACCES) {
    return coap_oscore_respond_resource(resource, request, addr, addr_len,
                                        &oscore, COAP_RESPONSE_CODE_FORBIDDEN,
                                        0, NULL, 0);
  }
  if (ret < 0) {
    return coap_oscore_respond_resource(
        resource, request, addr, addr_len, &oscore,
        COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE, 0, NULL, 0);
  }
  return coap_oscore_respond_resource(resource, request, addr, addr_len,
                                      &oscore, COAP_RESPONSE_CODE_DELETED, 0,
                                      NULL, 0);
}

#if IS_ENABLED(CONFIG_LICHEN_COAP_WAYPOINTS)
static const char *const waypoints_path[] = {"waypoints", NULL};
COAP_RESOURCE_DEFINE(waypoints, lichen_coap_server,
                     {
                         .get = lichen_waypoints_get_handler,
                         .post = lichen_waypoints_post_handler,
                         .path = waypoints_path,
                     });

static const char *const waypoint_detail_path[] = {"waypoints", "+", NULL};
COAP_RESOURCE_DEFINE(waypoint_detail, lichen_coap_server,
                     {
                         .get = lichen_waypoint_detail_get_handler,
                         .put = lichen_waypoint_detail_put_handler,
                         .del = lichen_waypoint_detail_delete_handler,
                         .path = waypoint_detail_path,
                     });
#endif
