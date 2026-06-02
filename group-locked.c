/*
 * Copyright (C) 2024-2026 Key9 Identity, Inc <k9.io>
 * Copyright (C) 2024-2026 Champ Clark III <cclark@k9.io>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <stdio.h>
#include <pthread.h>
#include <stdint.h>
#include <errno.h>

#include <nss.h>
#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#include <string.h>
#include <stdbool.h>

#include <curl/curl.h>
#include <json-c/json.h>

#include "k9.h"

extern char QUERY_GROUP_NAME_URL[DEFAULT_SIZE];
extern char QUERY_GROUP_GID_URL[DEFAULT_SIZE];
extern char QUERY_GROUP_ID_URL[DEFAULT_SIZE];

extern bool GETGRENT_K9_FLAG;

static int grent_index = 0;

void _nss_k9_resetgrent_index(void)
{
    grent_index = 0;
}

/* Store a string into the NSS-provided buffer, advance p/remaining. */
#define BUF_STORE(field, val)                                       \
    do {                                                            \
        const char *_v = (val);                                     \
        size_t _len = strlen(_v) + 1;                              \
        if ( _len > remaining )                                     \
            {                                                       \
                json_object_put(json_in);                          \
                *errnop = ERANGE;                                   \
                return NSS_STATUS_TRYAGAIN;                         \
            }                                                       \
        strlcpy(p, _v, remaining);                                 \
        (field) = p;                                               \
        p += _len;                                                 \
        remaining -= _len;                                         \
    } while (0)

/* Parse a numeric id field; rejects non-numeric, negative, or out-of-range values. */
#define PARSE_ID(dest, str)                                         \
    do {                                                            \
        const char *_s = (str);                                     \
        char *_end;                                                 \
        errno = 0;                                                  \
        long _v = strtol(_s, &_end, 10);                           \
        if ( errno != 0 || _end == _s || *_end != '\0'             \
             || _v < 0 || _v > (long)UINT32_MAX )                  \
            {                                                       \
                json_object_put(json_in);                          \
                Log("Invalid id value in JSON: '%s'", _s);         \
                return NSS_STATUS_UNAVAIL;                          \
            }                                                       \
        (dest) = (int)_v;                                          \
    } while (0)

/*
 * Carve the gr_mem pointer array out of the NSS buffer.
 * Aligns p to sizeof(char*), then reserves (cc+1) pointer slots.
 * Returns NSS_STATUS_TRYAGAIN via the macro if the buffer is too small.
 */
#define BUF_ALLOC_GRMEM(cc)                                                     \
    do {                                                                        \
        uintptr_t _align = (sizeof(char *) - ((uintptr_t)p % sizeof(char *)))  \
                           % sizeof(char *);                                    \
        size_t _ptrsz = (cc + 1) * sizeof(char *);                             \
        if ( _align + _ptrsz > remaining )                                      \
            {                                                                   \
                json_object_put(json_in);                                      \
                *errnop = ERANGE;                                               \
                return NSS_STATUS_TRYAGAIN;                                     \
            }                                                                   \
        p += _align;                                                            \
        remaining -= _align;                                                    \
        result->gr_mem = (char **)p;                                            \
        result->gr_mem[0] = NULL;                                               \
        p += _ptrsz;                                                            \
        remaining -= _ptrsz;                                                    \
    } while (0)

enum nss_status _nss_k9_getgrnam_r_locked(const char *name, struct group *result, char *buffer, size_t buflen, int *errnop)
{

    char *response = NULL;

    const char *j_members;

    int j_gid = -1;

    char tmp[MAX_GROUP_SIZE] = { 0 };
    char *members_ptr = NULL;
    char *token = NULL;
    int i = 0;

    struct json_object *json_in = NULL;
    json_object *string_obj;

    char *p = buffer;
    size_t remaining = buflen;

    if ( !Load_Config() )
        {
            *errnop = EAGAIN;
            return NSS_STATUS_UNAVAIL;
        }

    char lookup_url[8192] = { 0 };

    char *escaped_name = curl_easy_escape(NULL, name, 0);

    if ( escaped_name == NULL )
        {
            *errnop = EAGAIN;
            return NSS_STATUS_UNAVAIL;
        }

    snprintf(lookup_url, sizeof(lookup_url), "%s/%s", QUERY_GROUP_NAME_URL, escaped_name);
    lookup_url[ sizeof(lookup_url) - 1 ] = '\0';
    curl_free(escaped_name);

    response = Query_K9( lookup_url );

    if ( response == NULL )
        {
            Log("Group name %s not found.", name);
            return NSS_STATUS_NOTFOUND;
        }

    json_in = json_tokener_parse(response);

    if ( json_in == NULL )
        {
            Log("ERROR: Cannot parse JSON from API: '%s'", response);
            return NSS_STATUS_UNAVAIL;
        }

    json_object_object_get_ex(json_in, "error", &string_obj);

    if ( string_obj != NULL )
        {
	    free(response);
            json_object_put(json_in);
            Log("Error for the API: %s", response);
            return NSS_STATUS_UNAVAIL;
        }

    /* group name */

    json_object_object_get_ex(json_in, "group", &string_obj);

    if ( string_obj == NULL )
        {
            free(response);
            json_object_put(json_in);
            Log("Unable to locate group in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    BUF_STORE(result->gr_name, json_object_get_string(string_obj));

    /* gid */

    json_object_object_get_ex(json_in, "gid", &string_obj);

    if ( string_obj == NULL )
        {
            free(response);
            json_object_put(json_in);
            Log("Unable to locate gid in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    PARSE_ID(j_gid, json_object_get_string(string_obj));

    /* members */

    json_object_object_get_ex(json_in, "members", &string_obj);

    if ( string_obj == NULL )
        {
            free(response);
            json_object_put(json_in);
            Log("Unable to locate members in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    j_members = json_object_get_string(string_obj);

    result->gr_passwd = "x";
    result->gr_gid = j_gid;

    /* Count members (commas + 1) to size the pointer array */

    int cc = 1;
    for ( int a = 0; a < (int)strlen(j_members); a++ )
        {
            if ( j_members[a] == ',' ) cc++;
        }

    BUF_ALLOC_GRMEM(cc);

    strlcpy(tmp, j_members, sizeof(tmp));
    members_ptr = strtok_r(tmp, ",", &token);

    while (members_ptr != NULL)
        {
            size_t mlen = strlen(members_ptr) + 1;

            if ( mlen > remaining )
                {
                    free(response);
                    json_object_put(json_in);
                    *errnop = ERANGE;
                    return NSS_STATUS_TRYAGAIN;
                }

            strlcpy(p, members_ptr, remaining);
            result->gr_mem[i] = p;
            result->gr_mem[i + 1] = NULL;
            p += mlen;
            remaining -= mlen;

            members_ptr = strtok_r(NULL, ",", &token);
            i++;
        }

    free(response);
    json_object_put(json_in);

    return NSS_STATUS_SUCCESS;

}

enum nss_status _nss_k9_getgrgid_r_locked(gid_t gid, struct group *result, char *buffer, size_t buflen, int *errnop)
{

    char *response = NULL;

    const char *j_members;
    int j_gid = -1;

    char tmp[MAX_GROUP_SIZE] = { 0 };
    char *members_ptr = NULL;
    char *token = NULL;
    int i = 0;

    struct json_object *json_in = NULL;
    json_object *string_obj;

    char *p = buffer;
    size_t remaining = buflen;

    if ( !Load_Config() )
        {
            *errnop = EAGAIN;
            return NSS_STATUS_UNAVAIL;
        }

    char lookup_url[8192] = { 0 };

    snprintf(lookup_url, sizeof(lookup_url), "%s/%d", QUERY_GROUP_GID_URL, gid);
    lookup_url[ sizeof(lookup_url) - 1 ] = '\0';

    response = Query_K9( lookup_url );

    if ( response == NULL )
        {
            Log("GID %d not found.", gid);
            return NSS_STATUS_NOTFOUND;
        }

    json_in = json_tokener_parse(response);

    if ( json_in == NULL )
        {
            Log("ERROR: Cannot parse JSON from API: '%s'", response);
            return NSS_STATUS_UNAVAIL;
        }

    json_object_object_get_ex(json_in, "error", &string_obj);

    if ( string_obj != NULL )
        {
            free(response);
            json_object_put(json_in);
            Log("Error for the API: %s", response);
            return NSS_STATUS_UNAVAIL;
        }

    /* group name */

    json_object_object_get_ex(json_in, "group", &string_obj);

    if ( string_obj == NULL )
        {
            free(response);
            json_object_put(json_in);
            Log("Unable to locate group in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    BUF_STORE(result->gr_name, json_object_get_string(string_obj));

    /* gid */

    json_object_object_get_ex(json_in, "gid", &string_obj);

    if ( string_obj == NULL )
        {
            free(response);
            json_object_put(json_in);
            Log("Unable to locate gid in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    PARSE_ID(j_gid, json_object_get_string(string_obj));

    /* members */

    json_object_object_get_ex(json_in, "members", &string_obj);

    if ( string_obj == NULL )
        {
            free(response);
            json_object_put(json_in);
            Log("Unable to locate members in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    j_members = json_object_get_string(string_obj);

    result->gr_passwd = "x";
    result->gr_gid = j_gid;

    /* Count members (commas + 1) to size the pointer array */

    int cc = 1;
    for ( int a = 0; a < (int)strlen(j_members); a++ )
        {
            if ( j_members[a] == ',' ) cc++;
        }

    BUF_ALLOC_GRMEM(cc);

    strlcpy(tmp, j_members, sizeof(tmp));
    members_ptr = strtok_r(tmp, ",", &token);

    while (members_ptr != NULL)
        {
            size_t mlen = strlen(members_ptr) + 1;

            if ( mlen > remaining )
                {
                    free(response);
                    json_object_put(json_in);
                    *errnop = ERANGE;
                    return NSS_STATUS_TRYAGAIN;
                }

            strlcpy(p, members_ptr, remaining);
            result->gr_mem[i] = p;
            result->gr_mem[i + 1] = NULL;
            p += mlen;
            remaining -= mlen;

            members_ptr = strtok_r(NULL, ",", &token);
            i++;
        }

    free(response);
    json_object_put(json_in);

    return NSS_STATUS_SUCCESS;

}

enum nss_status _nss_k9_getgrent_r_locked(struct group *result, char *buffer, size_t buflen, int *errnop)
{

    char lookup_url[1024] = { 0 };
    char *response = NULL;

    const char *j_members = NULL;

    int j_gid = -1;

    char tmp[MAX_GROUP_SIZE] = { 0 };
    char *members_ptr = NULL;
    char *token = NULL;

    int i = 0;

    struct json_object *json_in = NULL;
    json_object *string_obj;

    char *p = buffer;
    size_t remaining = buflen;

    if ( !Load_Config() )
        {
            *errnop = EAGAIN;
            return NSS_STATUS_UNAVAIL;
        }

    if ( GETGRENT_K9_FLAG == false )
        {
            return NSS_STATUS_NOTFOUND;
        }

    grent_index++;

    snprintf(lookup_url, sizeof(lookup_url), "%s/%d", QUERY_GROUP_ID_URL, grent_index);
    lookup_url[ sizeof(lookup_url) - 1 ] = '\0';

    response = Query_K9( lookup_url );

    if ( response == NULL )
        {
            Log("ID %d not found.", grent_index);
            return NSS_STATUS_NOTFOUND;
        }

    json_in = json_tokener_parse(response);

    if ( json_in == NULL )
        {
            Log("ERROR: Cannot parse JSON from API: '%s'", response);
            return NSS_STATUS_UNAVAIL;
        }

    json_object_object_get_ex(json_in, "error", &string_obj);

    if ( string_obj != NULL )
        {
            free(response);
            json_object_put(json_in);
            Log("Error for the API: %s", response);
            return NSS_STATUS_UNAVAIL;
        }

    /* group name */

    json_object_object_get_ex(json_in, "group", &string_obj);

    if ( string_obj == NULL )
        {
            free(response);
            json_object_put(json_in);
            Log("Unable to locate group in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    BUF_STORE(result->gr_name, json_object_get_string(string_obj));

    /* gid */

    json_object_object_get_ex(json_in, "gid", &string_obj);

    if ( string_obj == NULL )
        {
            free(response);
            json_object_put(json_in);
            Log("Unable to locate gid in JSON");
            return NSS_STATUS_NOTFOUND;
        }

    PARSE_ID(j_gid, json_object_get_string(string_obj));

    /* members */

    json_object_object_get_ex(json_in, "members", &string_obj);

    if ( string_obj == NULL )
        {
            free(response);
            json_object_put(json_in);
            Log("Unable to locate members in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    j_members = json_object_get_string(string_obj);

    result->gr_passwd = "x";
    result->gr_gid = j_gid;

    /* Count members (commas + 1) to size the pointer array */

    int cc = 1;
    for ( int a = 0; a < (int)strlen(j_members); a++ )
        {
            if ( j_members[a] == ',' ) cc++;
        }

    BUF_ALLOC_GRMEM(cc);

    strlcpy(tmp, j_members, sizeof(tmp));
    members_ptr = strtok_r(tmp, ",", &token);

    while (members_ptr != NULL)
        {
            size_t mlen = strlen(members_ptr) + 1;

            if ( mlen > remaining )
                {
                    free(response);
                    json_object_put(json_in);
                    *errnop = ERANGE;
                    return NSS_STATUS_TRYAGAIN;
                }

            strlcpy(p, members_ptr, remaining);
            result->gr_mem[i] = p;
            result->gr_mem[i + 1] = NULL;
            p += mlen;
            remaining -= mlen;

            members_ptr = strtok_r(NULL, ",", &token);
            i++;
        }

    free(response);
    json_object_put(json_in);

    return NSS_STATUS_SUCCESS;

}
