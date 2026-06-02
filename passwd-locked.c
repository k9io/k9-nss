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
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <shadow.h>

#include <curl/curl.h>
#include <json-c/json.h>

#include "k9.h"

extern char QUERY_PASSWD_USERNAME_URL[DEFAULT_SIZE];
extern char QUERY_PASSWD_UID_URL[DEFAULT_SIZE];
extern char QUERY_PASSWD_ID_URL[DEFAULT_SIZE];

extern bool GETPWENT_K9_FLAG;

static int pwent_index = 0;

void _nss_k9_resetpwent_index(void)
{
    pwent_index = 0;
}

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

/* Store a string from json into the NSS-provided buffer, advance p/remaining. */
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

enum nss_status _nss_k9_getpwnam_r_locked(const char *name, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{

    char lookup_url[8192] = { 0 };
    char *response = NULL;

    int j_uid = -1;
    int j_gid = -1;

    struct json_object *json_in = NULL;
    json_object *string_obj;

    char *p = buffer;
    size_t remaining = buflen;

    if ( !Load_Config() )
        {
            *errnop = EAGAIN;
            return NSS_STATUS_UNAVAIL;
        }

    char *escaped_name = curl_easy_escape(NULL, name, 0);

    if ( escaped_name == NULL )
        {
            *errnop = EAGAIN;
            return NSS_STATUS_UNAVAIL;
        }

    snprintf(lookup_url, sizeof(lookup_url), "%s/%s", QUERY_PASSWD_USERNAME_URL, escaped_name);
    lookup_url[ sizeof(lookup_url) - 1 ] = '\0';
    curl_free(escaped_name);

    response = Query_K9( lookup_url );

    if ( response == NULL )
        {
            Log("User %s not found.", name);
            return NSS_STATUS_NOTFOUND;
        }

    json_in = json_tokener_parse(response);

    if ( json_in == NULL )
        {
	    free(response);
            Log("ERROR: Cannot parse JSON from API: '%s'", response);
            return NSS_STATUS_UNAVAIL;
        }

    json_object_object_get_ex(json_in, "error", &string_obj);

    if ( string_obj != NULL )
        {
            json_object_put(json_in);
            Log("Error for the API: %s", response);
            free(response);
            return NSS_STATUS_UNAVAIL;
        }

    /* username */

    json_object_object_get_ex(json_in, "username", &string_obj);

    if ( string_obj == NULL )
        {
	    free(response);
            json_object_put(json_in);
            Log("Unable to locate username in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    BUF_STORE(result->pw_name, json_object_get_string(string_obj));

    /* uid */

    json_object_object_get_ex(json_in, "uid", &string_obj);

    if ( string_obj == NULL )
        {
            free(response);
            json_object_put(json_in);
            Log("Unable to locate uid in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    PARSE_ID(j_uid, json_object_get_string(string_obj));

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

    /* shell */

    json_object_object_get_ex(json_in, "shell", &string_obj);

    if ( string_obj == NULL )
        {
            free(response);
            json_object_put(json_in);
            Log("Unable to locate shell in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    BUF_STORE(result->pw_shell, json_object_get_string(string_obj));

    /* home dir */

    json_object_object_get_ex(json_in, "home_dir", &string_obj);

    if ( string_obj == NULL )
        {
            free(response);
            json_object_put(json_in);
            Log("Unable to locate home_dir in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    BUF_STORE(result->pw_dir, json_object_get_string(string_obj));

    /* gecos */

    json_object_object_get_ex(json_in, "gecos", &string_obj);

    if ( string_obj == NULL )
        {
            free(response);
            json_object_put(json_in);
            Log("Unable to locate gecos in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    BUF_STORE(result->pw_gecos, json_object_get_string(string_obj));

    /* legacy passwd placeholder */

    BUF_STORE(result->pw_passwd, "x");

    result->pw_uid = j_uid;
    result->pw_gid = j_gid;

    free(response);
    json_object_put(json_in);

    if ( DEBUG_PASSWD == true )
        {
            printf("(_nss_k9_getpwnam_r_locked) RETURN: |%s:%s:%d:%d:%s:%s:%s|\n", result->pw_name, result->pw_passwd, result->pw_uid, result->pw_gid, result->pw_gecos, result->pw_dir, result->pw_shell);
        }

    return NSS_STATUS_SUCCESS;

}


enum nss_status _nss_k9_getpwuid_r_locked(uid_t uid, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{

    char lookup_url[8192] = { 0 };
    char *response = NULL;

    int j_uid = -1;
    int j_gid = -1;

    struct json_object *json_in = NULL;
    json_object *string_obj;

    char *p = buffer;
    size_t remaining = buflen;

    if ( !Load_Config() )
        {
            *errnop = EAGAIN;
            return NSS_STATUS_UNAVAIL;
        }

    snprintf(lookup_url, sizeof(lookup_url), "%s/%d", QUERY_PASSWD_UID_URL, uid);
    lookup_url[ sizeof(lookup_url) - 1 ] = '\0';

    response = Query_K9( lookup_url );

    if ( response == NULL )
        {
            Log("UID %d not found.", uid);
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
            json_object_put(json_in);
            Log("Error for the API: %s", response);
            free(response);
            return NSS_STATUS_UNAVAIL;
        }

    /* username */

    json_object_object_get_ex(json_in, "username", &string_obj);

    if ( string_obj == NULL )
        {
	    free(response);
            json_object_put(json_in);
            Log("Unable to locate username in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    BUF_STORE(result->pw_name, json_object_get_string(string_obj));

    /* uid */

    json_object_object_get_ex(json_in, "uid", &string_obj);

    if ( string_obj == NULL )
        {
            free(response);
            json_object_put(json_in);
            Log("Unable to locate uid in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    PARSE_ID(j_uid, json_object_get_string(string_obj));

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

    /* shell */

    json_object_object_get_ex(json_in, "shell", &string_obj);

    if ( string_obj == NULL )
        {
            free(response);
            json_object_put(json_in);
            Log("Unable to locate shell in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    BUF_STORE(result->pw_shell, json_object_get_string(string_obj));

    /* home dir */

    json_object_object_get_ex(json_in, "home_dir", &string_obj);

    if ( string_obj == NULL )
        {
            free(response);
            json_object_put(json_in);
            Log("Unable to locate home_dir in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    BUF_STORE(result->pw_dir, json_object_get_string(string_obj));

    /* gecos */

    json_object_object_get_ex(json_in, "gecos", &string_obj);

    if ( string_obj == NULL )
        {
            free(response);
            json_object_put(json_in);
            Log("Unable to locate gecos in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    BUF_STORE(result->pw_gecos, json_object_get_string(string_obj));

    /* legacy passwd placeholder */

    BUF_STORE(result->pw_passwd, "x");

    result->pw_uid = j_uid;
    result->pw_gid = j_gid;

    free(response);
    json_object_put(json_in);

    if ( DEBUG_PASSWD == true )
        {
            printf("(_nss_k9_getpwuid_r_locked) RETURN: |%s:%s:%d:%d:%s:%s:%s|\n", result->pw_name, result->pw_passwd, result->pw_uid, result->pw_gid, result->pw_gecos, result->pw_dir, result->pw_shell);
        }

    return NSS_STATUS_SUCCESS;

}

enum nss_status _nss_k9_getpwent_r_locked(struct passwd *result, char *buffer, size_t buflen, int *errnop)
{

    char lookup_url[8192] = { 0 };
    char *response = NULL;

    int j_uid = -1;
    int j_gid = -1;

    struct json_object *json_in = NULL;
    json_object *string_obj;

    char *p = buffer;
    size_t remaining = buflen;

    if ( !Load_Config() )
        {
            *errnop = EAGAIN;
            return NSS_STATUS_UNAVAIL;
        }

    if ( GETPWENT_K9_FLAG == false )
        {
            return NSS_STATUS_NOTFOUND;
        }

    pwent_index++;

    snprintf(lookup_url, sizeof(lookup_url), "%s/%d", QUERY_PASSWD_ID_URL, pwent_index);
    lookup_url[ sizeof(lookup_url) - 1 ] = '\0';

    response = Query_K9( lookup_url );

    if ( response == NULL )
        {
            Log("ID %d not found.", pwent_index);
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
            json_object_put(json_in);
            Log("Error for the API: %s", response);
            free(response);
            return NSS_STATUS_NOTFOUND;
        }

    /* username */

    json_object_object_get_ex(json_in, "username", &string_obj);

    if ( string_obj == NULL )
        {
            free(response);
            json_object_put(json_in);
            Log("Unable to locate username in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    BUF_STORE(result->pw_name, json_object_get_string(string_obj));

    /* uid */

    json_object_object_get_ex(json_in, "uid", &string_obj);

    if ( string_obj == NULL )
        {
            free(response);
            json_object_put(json_in);
            Log("Unable to locate uid in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    PARSE_ID(j_uid, json_object_get_string(string_obj));

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

    /* shell */

    json_object_object_get_ex(json_in, "shell", &string_obj);

    if ( string_obj == NULL )
        {
            free(response);
            json_object_put(json_in);
            Log("Unable to locate shell in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    BUF_STORE(result->pw_shell, json_object_get_string(string_obj));

    /* home dir */

    json_object_object_get_ex(json_in, "home_dir", &string_obj);

    if ( string_obj == NULL )
        {
            free(response);
            json_object_put(json_in);
            Log("Unable to locate home_dir in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    BUF_STORE(result->pw_dir, json_object_get_string(string_obj));

    /* gecos */

    json_object_object_get_ex(json_in, "gecos", &string_obj);

    if ( string_obj == NULL )
        {
            free(response);
            json_object_put(json_in);
            Log("Unable to locate gecos in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    BUF_STORE(result->pw_gecos, json_object_get_string(string_obj));

    /* legacy passwd placeholder */

    BUF_STORE(result->pw_passwd, "x");

    result->pw_uid = j_uid;
    result->pw_gid = j_gid;

    free(response);
    json_object_put(json_in);

    if ( DEBUG_PASSWD == true )
        {
            printf("(_nss_k9_getpwent_r_locked) RETURN: |%s:%s:%d:%d:%s:%s:%s|\n", result->pw_name, result->pw_passwd, result->pw_uid, result->pw_gid, result->pw_gecos, result->pw_dir, result->pw_shell);
        }

    return NSS_STATUS_SUCCESS;

}
