/*
 * Borrowed from telepathy
 *
 * Copyright (C) 2005-2009 Collabora Ltd. <http://www.collabora.co.uk/>
 * Copyright (C) 2005-2009 Nokia Corporation
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#ifndef DBUS_ASV_H__
#define DBUS_ASV_H__

#include <glib.h>
#include <glib/ghash.h>
#include <dbus/dbus-glib.h>

#ifdef __GNUC__
#  define DBUS_ASV_NULL_TERMINATED_ARGS	__attribute__((sentinel))
#  define DBUS_ASV_MUST_USE_RESULT	__attribute__((warn_unused_result))
#else
#  define DBUS_ASV_NULL_TERMINATED_ARGS
#  define DBUS_ASV_MUST_USE_RESULT
#endif

/* Define the types we are working with.  It is conceptually opaque. */
typedef GHashTable dbus_asv;
typedef GHashTableIter dbus_asv_iterator;

/* create a new dbus_asv instance */
dbus_asv *dbus_asv_new(const char *first_key, ...)
  DBUS_ASV_NULL_TERMINATED_ARGS DBUS_ASV_MUST_USE_RESULT;

/* destroy a dbus_asv instance */
void dbus_asv_destroy(const dbus_asv *asv);

/* how many entries are in this dbus_asv */
size_t dbus_asv_size(const dbus_asv *asv);

/* get the GType of a dbus_asv */
GType dbus_asv_gtype(void);

/* iterate a dbus_asv */
void dbus_asv_iter_init(dbus_asv_iterator *iter, const dbus_asv *asv);
gboolean dbus_asv_iter_next(dbus_asv_iterator *iter, void *key, void *value);

/* access a boolean value */
gboolean dbus_asv_get_boolean(const dbus_asv *asv, const char *key,
                              gboolean *valid);
void dbus_asv_set_boolean(dbus_asv *asv, const char *key, gboolean value);

/* access a string value */
const char *dbus_asv_get_string(const dbus_asv *asv, const char *key);
void dbus_asv_set_string(dbus_asv *asv, const char *key, const char *value,
                         int take_ownership);

/* access a signed int32 value */
int32_t dbus_asv_get_int32(const dbus_asv *asv, const char *key,
                          gboolean *valid);
void dbus_asv_set_int32(dbus_asv *asv, const char *key, int32_t value);

/* access an unsigned int32 value */
uint32_t dbus_asv_get_uint32(const dbus_asv *asv, const char *key,
                            gboolean *valid);
void dbus_asv_set_uint32(dbus_asv *asv, const char *key, uint32_t value);

/* access a signed int64 value */
int64_t dbus_asv_get_int64(const dbus_asv *asv, const char *key,
                          gboolean *valid);
void dbus_asv_set_int64(dbus_asv *asv, const char *key, int64_t value);

/* access an unsigned int64 value */
uint64_t dbus_asv_get_uint64(const dbus_asv *asv, const char *key,
                            gboolean *valid);
void dbus_asv_set_uint64(dbus_asv *asv, const char *key, uint64_t value);

/* lookup a key */
const GValue *dbus_asv_lookup(const dbus_asv *asv, const char *key);

#endif /* DBUS_ASV_H__ */
