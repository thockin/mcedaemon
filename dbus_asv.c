/*
 * Borrowed from telepathy.
 *
 * Copyright(C) 2005-2008 Collabora Ltd. <http://www.collabora.co.uk/>
 * Copyright(C) 2005-2008 Nokia Corporation
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or(at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dbus/dbus.h>
#include <glib.h>
#include <glib/ghash.h>
#include <glib-object.h>
#include <gobject/gvaluecollector.h>
#include "dbus_asv.h"

/*
 * new_g_value:
 * @type: The type desired for the new GValue
 *
 * Slice-allocate an empty GValue. new_boolean_g_value() and similar
 * functions are likely to be more convenient to use for the types supported.
 *
 * Returns: a newly allocated, newly initialized GValue, to be freed with
 * free_g_value().
 */
static GValue *
new_g_value(GType type)
{
	GValue *value = g_slice_new0(GValue);
	g_value_init(value, type);
	return value;
}

/*
 * free_g_value:
 * @value: A GValue which was allocated with the g_slice API
 *
 * Unset and free a slice-allocated GValue.
 */
static void
free_g_value(GValue *value)
{
	g_value_unset(value);
	g_slice_free(GValue, value);
}

/*
 * new_boolean_g_value:
 * @b: a boolean value
 *
 * Slice-allocate and initialize a GValue. This function is convenient to
 * use when constructing hash tables from string to GValue, for example.
 *
 * Returns: a GValue of type G_TYPE_BOOLEAN with value @b, to be freed with
 * free_g_value().
 */
static GValue *
new_boolean_g_value(gboolean b)
{
	GValue *v = new_g_value(G_TYPE_BOOLEAN);
	g_value_set_boolean(v, b);
	return v;
}

/*
 * new_int_g_value:
 * @n: an integer
 *
 * Slice-allocate and initialize a GValue. This function is convenient to
 * use when constructing hash tables from string to GValue, for example.
 *
 * Returns: a GValue of type G_TYPE_INT with value @n, to be freed with
 * free_g_value().
 */
static GValue *
new_int_g_value(int n)
{
	GValue *v = new_g_value(G_TYPE_INT);
	g_value_set_int(v, n);
	return v;
}

/*
 * new_int64_g_value:
 * @n: a 64-bit integer
 *
 * Slice-allocate and initialize a GValue. This function is convenient to
 * use when constructing hash tables from string to GValue, for example.
 *
 * Returns: a GValue of type G_TYPE_INT64 with value @n, to be freed with
 * free_g_value().
 */
static GValue *
new_int64_g_value(int64_t n)
{
	GValue *v = new_g_value(G_TYPE_INT64);
	g_value_set_int64(v, n);
	return v;
}

/*
 * new_uint_g_value:
 * @n: an unsigned integer
 *
 * Slice-allocate and initialize a GValue. This function is convenient to
 * use when constructing hash tables from string to GValue, for example.
 *
 * Returns: a GValue of type G_TYPE_UINT with value @n, to be freed with
 * free_g_value().
 */
static GValue *
new_uint_g_value(unsigned n)
{
	GValue *v = new_g_value(G_TYPE_UINT);
	g_value_set_uint(v, n);
	return v;
}

/*
 * new_uint64_g_value:
 * @n: a 64-bit unsigned integer
 *
 * Slice-allocate and initialize a GValue. This function is convenient to
 * use when constructing hash tables from string to GValue, for example.
 *
 * Returns: a GValue of type G_TYPE_UINT64 with value @n, to be freed with
 * free_g_value().
 */
static GValue *
new_uint64_g_value(uint64_t n)
{
	GValue *v = new_g_value(G_TYPE_UINT64);
	g_value_set_uint64(v, n);
	return v;
}

/*
 * new_string_g_value:
 * @string: a string to be copied into the value
 *
 * Slice-allocate and initialize a GValue. This function is convenient to
 * use when constructing hash tables from string to GValue, for example.
 *
 * Returns: a GValue of type G_TYPE_STRING whose value is a copy of @string,
 * to be freed with free_g_value().
 */
static GValue *
new_string_g_value(const char *string, int take_ownership)
{
	GValue *v = new_g_value(G_TYPE_STRING);
	if (take_ownership) {
		g_value_take_string(v, (char *)string);
	} else {
		g_value_set_string(v, string);
	}
	return v;
}

/*
 * dbus_asv_new:
 * @first_key: the name of the first key(or NULL)
 * @...: type and value for the first key, followed by a NULL-terminated list
 *  of(key, type, value) tuples
 *
 * Creates a new dbus_asv for use with a{sv} maps, containing the values
 * passed in as parameters.
 *
 * Parameters are stored in slice-allocated GValues and should be set using
 * dbus_asv_set_*() and retrieved using dbus_asv_get_*().
 *
 * Example:
 *   dbus_asv *parameters = dbus_asv_new(
 *       "answer", G_TYPE_INT, 42,
 *       "question", G_TYPE_STRING, "We just don't know",
 *       NULL);
 *
 * Allocated values will be automatically free'd when overwritten, removed or
 * the hash table destroyed with g_hash_table_destroy().
 *
 * Returns: a newly created dbus_asv for storing a{sv} maps, free with
 * dbus_asv_destroy().
 */
GHashTable *
dbus_asv_new(const char *first_key, ...)
{
	va_list args;
	const char *key;
	GType type;
	GValue *value;
	char *error = NULL; /* NB: not a GError! */

	/* create a GHashTable */
	GHashTable *asv = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
	                                        (GDestroyNotify)free_g_value);

	va_start(args, first_key);
	for (key = first_key; key != NULL; key = va_arg(args, const char *)) {
		type = va_arg(args, GType);

		value = new_g_value(type);
		G_VALUE_COLLECT(value, args, 0, &error);

		if (error != NULL) {
			g_critical("key %s: %s", key, error);
			g_free(error);
			error = NULL;
			free_g_value(value);
			continue;
		}

		g_hash_table_insert(asv, (char *)key, value);
	}
	va_end(args);

	return asv;
}

/*
 * dbus_asv_destroy:
 * @asv: a dbus_asv
 *
 * Destroy and clean up a dbus_asv.
 */
void
dbus_asv_destroy(const GHashTable *asv)
{
	g_hash_table_destroy((GHashTable *)asv);
}

/*
 * dbus_asv_size:
 * @asv: a dbus_asv
 *
 * Return the size of @asv.
 */
size_t
dbus_asv_size(const GHashTable *asv)
{
	return g_hash_table_size((GHashTable *)asv);
}

void
dbus_asv_iter_init(GHashTableIter *iter, const GHashTable *asv)
{
	g_hash_table_iter_init(iter, (GHashTable *)asv);
}

gboolean
dbus_asv_iter_next(GHashTableIter *iter, void *key, void *value)
{
	return g_hash_table_iter_next(iter, (gpointer *)key, (gpointer *)value);
}

/* Get the GType of a D-Bus "a{sv}" type. */
GType
dbus_asv_gtype()
{
	static GType t;
	static int initalized = 0;
	if (!initalized) {
		t = dbus_g_type_get_map("GHashTable",
		                        G_TYPE_STRING, G_TYPE_VALUE);
		initalized = 1;
	}
	return t;
}

/*
 * dbus_asv_get_boolean:
 * @asv: A dbus_asv where the keys are strings and the values are GValues
 * @key: The key to look up
 * @valid: Either %NULL, or a location to store %TRUE if the key actually
 *  exists and has a boolean value
 *
 * If a value for @key in @asv is present and boolean, return it,
 * and set *@valid to %TRUE if @valid is not %NULL.
 *
 * Otherwise return %FALSE, and set *@valid to %FALSE if @valid is not %NULL.
 *
 * Returns: a boolean value for @key
 */
gboolean
dbus_asv_get_boolean(const GHashTable *asv, const char *key, gboolean *valid)
{
	GValue *value;

	g_return_val_if_fail(asv != NULL, FALSE);
	g_return_val_if_fail(key != NULL, FALSE);

	value = g_hash_table_lookup((GHashTable *)asv, key);

	if (value == NULL || !G_VALUE_HOLDS_BOOLEAN(value)) {
			if (valid != NULL)
				*valid = FALSE;

			return FALSE;
		}

	if (valid != NULL)
		*valid = TRUE;

	return g_value_get_boolean(value);
}

/*
 * dbus_asv_set_boolean:
 * @asv: a dbus_asv created with dbus_asv_new()
 * @key: string key
 * @value: value
 *
 * Stores the value in the map.
 */
void
dbus_asv_set_boolean(GHashTable *asv, const char *key, gboolean value)
{
	g_return_if_fail(asv != NULL);
	g_return_if_fail(key != NULL);

	g_hash_table_insert(asv, (char *)key, new_boolean_g_value(value));
}

/*
 * dbus_asv_get_string:
 * @asv: A dbus_asv where the keys are strings and the values are GValues
 * @key: The key to look up
 *
 * If a value for @key in @asv is present and is a string, return it.
 *
 * Otherwise return %NULL.
 *
 * The returned value is not copied, and is only valid as long as the value
 * for @key in @asv is not removed or altered. Copy it with g_strdup() if you
 * need to keep it for longer.
 *
 * Returns: the string value of @key, or %NULL
 */
const char *
dbus_asv_get_string(const GHashTable *asv, const char *key)
{
	GValue *value;

	g_return_val_if_fail(asv != NULL, NULL);
	g_return_val_if_fail(key != NULL, NULL);

	value = g_hash_table_lookup((GHashTable *)asv, key);

	if (value == NULL || !G_VALUE_HOLDS_STRING(value))
		return NULL;

	return g_value_get_string(value);
}

/*
 * dbus_asv_set_string:
 * @asv: a dbus_asv created with dbus_asv_new()
 * @key: string key
 * @value: value
 *
 * Stores the value in the map.
 */
void
dbus_asv_set_string(GHashTable *asv, const char *key, const char *value,
                    int take_ownership)
{
	g_return_if_fail(asv != NULL);
	g_return_if_fail(key != NULL);
	g_hash_table_insert(asv, (char *)key,
	                    new_string_g_value(value, take_ownership));
}

/*
 * dbus_asv_get_int32:
 * @asv: A dbus_asv where the keys are strings and the values are GValues
 * @key: The key to look up
 * @valid: Either %NULL, or a location in which to store %TRUE on success or
 *    %FALSE on failure
 *
 * If a value for @key in @asv is present, has an integer type used by
 * dbus-glib(guchar, gint, guint, int64_t or uint64_t) and fits in the
 * range of a int32_t, return it, and if @valid is not %NULL, set *@valid to
 * %TRUE.
 *
 * Otherwise, return 0, and if @valid is not %NULL, set *@valid to %FALSE.
 *
 * Returns: the 32-bit signed integer value of @key, or 0
 */
int32_t
dbus_asv_get_int32(const GHashTable *asv, const char *key, gboolean *valid)
{
	int64_t i;
	uint64_t u;
	int32_t ret;
	GValue *value;

	g_return_val_if_fail(asv != NULL, 0);
	g_return_val_if_fail(key != NULL, 0);

	value = g_hash_table_lookup((GHashTable *)asv, key);

	if (value == NULL)
		goto return_invalid;

	switch (G_VALUE_TYPE(value)) {
		case G_TYPE_UCHAR:
			ret = g_value_get_uchar(value);
			break;

		case G_TYPE_UINT:
			u = g_value_get_uint(value);

			if (G_UNLIKELY(u > INT32_MAX))
				goto return_invalid;

			ret = u;
			break;

		case G_TYPE_INT:
			ret = g_value_get_int(value);
			break;

		case G_TYPE_INT64:
			i = g_value_get_int64(value);

			if (G_UNLIKELY(i < G_MININT32 || i > INT32_MAX))
				goto return_invalid;

			ret = i;
			break;

		case G_TYPE_UINT64:
			u = g_value_get_uint64(value);

			if (G_UNLIKELY(u > INT32_MAX))
				goto return_invalid;

			ret = u;
			break;

		default:
			goto return_invalid;
	}

	if (valid != NULL)
		*valid = TRUE;

	return ret;

return_invalid:
	if (valid != NULL)
		*valid = FALSE;

	return 0;
}

/*
 * dbus_asv_set_int32:
 * @asv: a dbus_asv created with dbus_asv_new()
 * @key: string key
 * @value: value
 *
 * Stores the value in the map.
 */
void
dbus_asv_set_int32(GHashTable *asv, const char *key, int32_t value)
{
	g_return_if_fail(asv != NULL);
	g_return_if_fail(key != NULL);

	g_hash_table_insert(asv, (char *)key, new_int_g_value(value));
}

/*
 * dbus_asv_get_uint32:
 * @asv: A dbus_asv where the keys are strings and the values are GValues
 * @key: The key to look up
 * @valid: Either %NULL, or a location in which to store %TRUE on success or
 *    %FALSE on failure
 *
 * If a value for @key in @asv is present, has an integer type used by
 * dbus-glib(guchar, gint, guint, int64_t or uint64_t) and fits in the
 * range of a uint32_t, return it, and if @valid is not %NULL, set *@valid to
 * %TRUE.
 *
 * Otherwise, return 0, and if @valid is not %NULL, set *@valid to %FALSE.
 *
 * Returns: the 32-bit unsigned integer value of @key, or 0
 */
uint32_t
dbus_asv_get_uint32(const GHashTable *asv, const char *key, gboolean *valid)
{
	int64_t i;
	uint64_t u;
	uint32_t ret;
	GValue *value;

	g_return_val_if_fail(asv != NULL, 0);
	g_return_val_if_fail(key != NULL, 0);

	value = g_hash_table_lookup((GHashTable *)asv, key);

	if (value == NULL)
		goto return_invalid;

	switch (G_VALUE_TYPE(value)) {
		case G_TYPE_UCHAR:
			ret = g_value_get_uchar(value);
			break;

		case G_TYPE_UINT:
			ret = g_value_get_uint(value);
			break;

		case G_TYPE_INT:
			i = g_value_get_int(value);

			if (G_UNLIKELY(i < 0))
				goto return_invalid;

			ret = i;
			break;

		case G_TYPE_INT64:
			i = g_value_get_int64(value);

			if (G_UNLIKELY(i < 0 || i > UINT32_MAX))
				goto return_invalid;

			ret = i;
			break;

		case G_TYPE_UINT64:
			u = g_value_get_uint64(value);

			if (G_UNLIKELY(u > UINT32_MAX))
				goto return_invalid;

			ret = u;
			break;

		default:
			goto return_invalid;
	}

	if (valid != NULL)
		*valid = TRUE;

	return ret;

return_invalid:
	if (valid != NULL)
		*valid = FALSE;

	return 0;
}

/*
 * dbus_asv_set_uint32:
 * @asv: a dbus_asv created with dbus_asv_new()
 * @key: string key
 * @value: value
 *
 * Stores the value in the map.
 */
void
dbus_asv_set_uint32(GHashTable *asv, const char *key, uint32_t value)
{
	g_return_if_fail(asv != NULL);
	g_return_if_fail(key != NULL);

	g_hash_table_insert(asv, (char *)key, new_uint_g_value(value));
}

/*
 * dbus_asv_get_int64:
 * @asv: A dbus_asv where the keys are strings and the values are GValues
 * @key: The key to look up
 * @valid: Either %NULL, or a location in which to store %TRUE on success or
 *    %FALSE on failure
 *
 * If a value for @key in @asv is present, has an integer type used by
 * dbus-glib(guchar, gint, guint, int64_t or uint64_t) and fits in the
 * range of a int64_t, return it, and if @valid is not %NULL, set *@valid to
 * %TRUE.
 *
 * Otherwise, return 0, and if @valid is not %NULL, set *@valid to %FALSE.
 *
 * Returns: the 64-bit signed integer value of @key, or 0
 */
int64_t
dbus_asv_get_int64(const GHashTable *asv, const char *key, gboolean *valid)
{
	int64_t ret;
	uint64_t u;
	GValue *value;

	g_return_val_if_fail(asv != NULL, 0);
	g_return_val_if_fail(key != NULL, 0);

	value = g_hash_table_lookup((GHashTable *)asv, key);

	if (value == NULL)
		goto return_invalid;

	switch (G_VALUE_TYPE(value)) {
		case G_TYPE_UCHAR:
			ret = g_value_get_uchar(value);
			break;

		case G_TYPE_UINT:
			ret = g_value_get_uint(value);
			break;

		case G_TYPE_INT:
			ret = g_value_get_int(value);
			break;

		case G_TYPE_INT64:
			ret = g_value_get_int64(value);
			break;

		case G_TYPE_UINT64:
			u = g_value_get_uint64(value);

			if (G_UNLIKELY(u > (uint64_t)INT64_MAX))
				goto return_invalid;

			ret = u;
			break;

		default:
			goto return_invalid;
	}

	if (valid != NULL)
		*valid = TRUE;

	return ret;

return_invalid:
	if (valid != NULL)
		*valid = FALSE;

	return 0;
}

/*
 * dbus_asv_set_int64:
 * @asv: a dbus_asv created with dbus_asv_new()
 * @key: string key
 * @value: value
 *
 * Stores the value in the map.
 */
void
dbus_asv_set_int64(GHashTable *asv, const char *key, int64_t value)
{
	g_return_if_fail(asv != NULL);
	g_return_if_fail(key != NULL);

	g_hash_table_insert(asv, (char *)key, new_int64_g_value(value));
}

/*
 * dbus_asv_get_uint64:
 * @asv: A dbus_asv where the keys are strings and the values are GValues
 * @key: The key to look up
 * @valid: Either %NULL, or a location in which to store %TRUE on success or
 *    %FALSE on failure
 *
 * If a value for @key in @asv is present, has an integer type used by
 * dbus-glib(guchar, gint, guint, int64_t or uint64_t) and is non-negative,
 * return it, and if @valid is not %NULL, set *@valid to %TRUE.
 *
 * Otherwise, return 0, and if @valid is not %NULL, set *@valid to %FALSE.
 *
 * Returns: the 64-bit unsigned integer value of @key, or 0
 */
uint64_t
dbus_asv_get_uint64(const GHashTable *asv, const char *key, gboolean *valid)
{
	int64_t tmp;
	uint64_t ret;
	GValue *value;

	g_return_val_if_fail(asv != NULL, 0);
	g_return_val_if_fail(key != NULL, 0);

	value = g_hash_table_lookup((GHashTable *)asv, key);

	if (value == NULL)
		goto return_invalid;

	switch (G_VALUE_TYPE(value)) {
		case G_TYPE_UCHAR:
			ret = g_value_get_uchar(value);
			break;

		case G_TYPE_UINT:
			ret = g_value_get_uint(value);
			break;

		case G_TYPE_INT:
			tmp = g_value_get_int(value);

			if (G_UNLIKELY(tmp < 0))
				goto return_invalid;

			ret = tmp;
			break;

		case G_TYPE_INT64:
			tmp = g_value_get_int64(value);

			if (G_UNLIKELY(tmp < 0))
				goto return_invalid;

			ret = tmp;
			break;

		case G_TYPE_UINT64:
			ret = g_value_get_uint64(value);
			break;

		default:
			goto return_invalid;
	}

	if (valid != NULL)
		*valid = TRUE;

	return ret;

return_invalid:
	if (valid != NULL)
		*valid = FALSE;

	return 0;
}

/*
 * dbus_asv_set_uint64:
 * @asv: a dbus_asv created with dbus_asv_new()
 * @key: string key
 * @value: value
 *
 * Stores the value in the map.
 */
void
dbus_asv_set_uint64(GHashTable *asv, const char *key, uint64_t value)
{
	g_return_if_fail(asv != NULL);
	g_return_if_fail(key != NULL);

	g_hash_table_insert(asv, (char *)key, new_uint64_g_value(value));
}

/*
 * dbus_asv_lookup:
 * @asv: A dbus_asv where the keys are strings and the values are GValues
 * @key: The key to look up
 *
 * If a value for @key in @asv is present, return it. Otherwise return %NULL.
 *
 * The returned value is not copied, and is only valid as long as the value
 * for @key in @asv is not removed or altered. Copy it with(for instance)
 * g_value_copy() if you need to keep it for longer.
 *
 * Returns: the value of @key, or %NULL
 */
const GValue *
dbus_asv_lookup(const GHashTable *asv, const char *key)
{
	g_return_val_if_fail(asv != NULL, NULL);
	g_return_val_if_fail(key != NULL, NULL);

	return g_hash_table_lookup((GHashTable *)asv, key);
}
