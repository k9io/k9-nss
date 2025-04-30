/*
 * Copyright (C) 2024 Key9 Identity, Inc <k9.io>
 * Copyright (C) 2024 Champ Clark III <cclark@k9.io>
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

enum nss_status _nss_k9_getpwnam_r_locked(const char *name, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{

    char lookup_url[8192] = { 0 };
    char *response = NULL;

    int j_uid = -1; 			/* DEBUG : Dont want to accidently give up root */
    int j_gid = -1; 			/* DEBUG : Dont want to accidently give up root */

    struct json_object *json_in = NULL;
    json_object *string_obj;

    Load_Config();

    snprintf(lookup_url, sizeof(lookup_url), "%s/%s", QUERY_PASSWD_USERNAME_URL, name);
    lookup_url[ sizeof(lookup_url) - 1 ] = '\0';

    response = Query_K9( lookup_url );

    if ( response == NULL )
        {
            Log("User %s not found.", name);
            return NSS_STATUS_NOTFOUND;
        }

    /* Parse incoming JSON */

    json_in = json_tokener_parse(response);

    if ( json_in == NULL )
        {
            json_object_put(json_in);

            Log("ERROR: Cannot parse JSON from API: '%s'", response);
            return NSS_STATUS_UNAVAIL;
        }

    /* Look for a key named "error".  There is a problem upstream if we get JSON with an "error" */

    json_object_object_get_ex(json_in, "error", &string_obj);

    if ( string_obj != NULL )
        {
            json_object_put(json_in);
            Log("Error for the API: %s", response);
            return NSS_STATUS_UNAVAIL;
        }

    /* username */

    json_object_object_get_ex(json_in, "username", &string_obj);

    if ( string_obj == NULL )
        {
            json_object_put(json_in);

            Log("Unable to locate username in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    result->pw_name = malloc( MAX_USERNAME_SIZE * sizeof(char *) );
    memset(result->pw_name, 0, MAX_USERNAME_SIZE);
    strlcpy( result->pw_name, json_object_get_string(string_obj), MAX_USERNAME_SIZE);

    /* uid */

    json_object_object_get_ex(json_in, "uid", &string_obj);

    if ( string_obj == NULL )
        {
            json_object_put(json_in);

            Log("Unable to locate uid in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    j_uid = atoi(json_object_get_string(string_obj));

    /* gid */

    json_object_object_get_ex(json_in, "gid", &string_obj);

    if ( string_obj == NULL )
        {
            json_object_put(json_in);

            Log("Unable to locate gid in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    j_gid = atoi(json_object_get_string(string_obj));

    /* shell */

    json_object_object_get_ex(json_in, "shell", &string_obj);

    if ( string_obj == NULL )
        {
            json_object_put(json_in);

            Log("Unable to locate shell in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    result->pw_shell = malloc( MAX_SHELL_SIZE * sizeof(char *) );
    memset(result->pw_shell, 0, MAX_SHELL_SIZE);
    strlcpy( result->pw_shell, json_object_get_string(string_obj), MAX_SHELL_SIZE);

    /* home dir */

    json_object_object_get_ex(json_in, "home_dir", &string_obj);

    if ( string_obj == NULL )
        {
            json_object_put(json_in);

            Log("Unable to locate home_dir in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    result->pw_dir = malloc( MAX_HOME_DIR_SIZE * sizeof(char *) );
    memset(result->pw_dir, 0, MAX_HOME_DIR_SIZE);
    strlcpy( result->pw_dir, json_object_get_string(string_obj), MAX_HOME_DIR_SIZE);

    /* gecos */

    json_object_object_get_ex(json_in, "gecos", &string_obj);

    if ( string_obj == NULL )
        {
            json_object_put(json_in);

            Log("Unable to locate gecos in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    result->pw_gecos = malloc( MAX_GECOS_SIZE * sizeof(char *) );
    memset(result->pw_gecos, 0, MAX_GECOS_SIZE);
    strlcpy( result->pw_gecos, json_object_get_string(string_obj), MAX_GECOS_SIZE);

    /* legacy passwd placeholder */

    result->pw_passwd = malloc( 2 * sizeof(char *) );
    memset(result->pw_gecos, 0, 2);
    strlcpy( result->pw_passwd, "x", 2);

    result->pw_uid = j_uid;
    result->pw_gid = j_gid;

    json_object_put(json_in);

    if ( DEBUG_PASSWD == true )
        {
            printf("(_nss_k9_getpwnam_r_locked) RETURN: |%s:%s:%d:%d:%s:%s:%s|\n", result->pw_name, result->pw_passwd, result->pw_uid, result->pw_gid, result->pw_gecos, result->pw_dir, result->pw_shell);
        }

    return NSS_STATUS_SUCCESS ;

}


enum nss_status _nss_k9_getpwuid_r_locked(uid_t uid, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{

    char lookup_url[8192] = { 0 };
    char *response = NULL;

    int j_uid = -1; 			/* DEBUG : Dont want to accidently give up root */
    int j_gid = -1; 			/* DEBUG : Dont want to accidently give up root */

    struct json_object *json_in = NULL;
    json_object *string_obj;

    Load_Config();

    snprintf(lookup_url, sizeof(lookup_url), "%s/%d",QUERY_PASSWD_UID_URL, uid);

    lookup_url[ sizeof(lookup_url) - 1 ] = '\0';

    response = Query_K9( lookup_url );

    if ( response == NULL )
        {
            Log("UID %d not found.", uid);
            return NSS_STATUS_NOTFOUND;
        }

    /* Parse incoming JSON */

    json_in = json_tokener_parse(response);

    if ( json_in == NULL )
        {
            Log("ERROR: Cannot parse JSON from API: '%s'", response);
            return NSS_STATUS_UNAVAIL;
        }

    /* Look for a key named "error".  There is a problem upstream if we get JSON with an "error" */

    json_object_object_get_ex(json_in, "error", &string_obj);

    if ( string_obj != NULL )
        {
            json_object_put(json_in);
            Log("Error for the API: %s", response);
            return NSS_STATUS_UNAVAIL;
        }

    /* username */

    json_object_object_get_ex(json_in, "username", &string_obj);

    if ( string_obj == NULL )
        {
            json_object_put(json_in);

            Log("Unable to locate username in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    result->pw_name = malloc( MAX_USERNAME_SIZE * sizeof(char *) );
    memset(result->pw_name, 0, MAX_USERNAME_SIZE);
    strlcpy( result->pw_name, json_object_get_string(string_obj), MAX_USERNAME_SIZE);

    /* uid */

    json_object_object_get_ex(json_in, "uid", &string_obj);

    if ( string_obj == NULL )
        {
            json_object_put(json_in);

            Log("Unable to locate uid in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    j_uid = atoi(json_object_get_string(string_obj));

    /* gid */

    json_object_object_get_ex(json_in, "gid", &string_obj);

    if ( string_obj == NULL )
        {
            json_object_put(json_in);

            Log("Unable to locate gid in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    j_gid = atoi(json_object_get_string(string_obj));

    /* shell */

    json_object_object_get_ex(json_in, "shell", &string_obj);

    if ( string_obj == NULL )
        {
            json_object_put(json_in);

            Log("Unable to locate shell in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    result->pw_shell = malloc( MAX_SHELL_SIZE * sizeof(char *) );
    memset(result->pw_shell, 0, MAX_SHELL_SIZE);
    strlcpy( result->pw_shell, json_object_get_string(string_obj), MAX_SHELL_SIZE);

    /* home dir */

    json_object_object_get_ex(json_in, "home_dir", &string_obj);

    if ( string_obj == NULL )
        {
            json_object_put(json_in);

            Log("Unable to locate home_dir in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    result->pw_dir = malloc( MAX_HOME_DIR_SIZE * sizeof(char *) );
    memset(result->pw_dir, 0, MAX_HOME_DIR_SIZE);
    strlcpy( result->pw_dir, json_object_get_string(string_obj), MAX_HOME_DIR_SIZE);

    /* gecos */

    json_object_object_get_ex(json_in, "gecos", &string_obj);

    if ( string_obj == NULL )
        {
            json_object_put(json_in);

            Log("Unable to locate gecos in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    result->pw_gecos = malloc( MAX_GECOS_SIZE * sizeof(char *) );
    memset(result->pw_gecos, 0, MAX_GECOS_SIZE);
    strlcpy( result->pw_gecos, json_object_get_string(string_obj), MAX_GECOS_SIZE);

    /* legacy passwd placeholder */

    result->pw_passwd = malloc( 2 * sizeof(char *) );
    memset(result->pw_gecos, 0, 2);
    strlcpy( result->pw_passwd, "x", 2);

    result->pw_uid = j_uid;
    result->pw_gid = j_gid;

    json_object_put(json_in);

    if ( DEBUG_PASSWD == true )
        {
            printf("(_nss_k9_getpwuid_r_locked) RETURN: |%s:%s:%d:%d:%s:%s:%s|\n", result->pw_name, result->pw_passwd, result->pw_uid, result->pw_gid, result->pw_gecos, result->pw_dir, result->pw_shell);
        }

    return NSS_STATUS_SUCCESS ;

}

enum nss_status _nss_k9_getpwent_r_locked(struct passwd *result, char *buffer, size_t buflen, int *errnop)
{

    char lookup_url[8192] = { 0 };
    char *response = NULL;

    int j_uid = -1;                     /* DEBUG : Dont want to accidently give up root */
    int j_gid = -1;                     /* DEBUG : Dont want to accidently give up root */

    struct json_object *json_in = NULL;
    json_object *string_obj;

    Load_Config();

    static int i = 0;
    i++;

    snprintf(lookup_url, sizeof(lookup_url), "%s/%d", QUERY_PASSWD_ID_URL, i);
    lookup_url[ sizeof(lookup_url) - 1 ] = '\0';

    response = Query_K9( lookup_url );

    if ( response == NULL )
        {
            Log("ID %d not found.", i);
            return NSS_STATUS_NOTFOUND;
        }

    /* Parse incoming JSON */

    json_in = json_tokener_parse(response);

    if ( json_in == NULL )
        {
            Log("ERROR: Cannot parse JSON from API: '%s'", response);
            return NSS_STATUS_UNAVAIL;
        }

    /* Look for a key named "error".  There is a problem upstream if we get JSON with an "error" */

    json_object_object_get_ex(json_in, "error", &string_obj);

    if ( string_obj != NULL )
        {
            json_object_put(json_in);
            Log("Error for the API: %s", response);
            return NSS_STATUS_NOTFOUND;
        }

    /* username */

    json_object_object_get_ex(json_in, "username", &string_obj);

    if ( string_obj == NULL )
        {
            json_object_put(json_in);

            Log("Unable to locate username in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    result->pw_name = malloc( MAX_USERNAME_SIZE * sizeof(char *) );
    memset(result->pw_name, 0, MAX_USERNAME_SIZE);
    strlcpy( result->pw_name, json_object_get_string(string_obj), MAX_USERNAME_SIZE);

    /* uid */

    json_object_object_get_ex(json_in, "uid", &string_obj);

    if ( string_obj == NULL )
        {
            json_object_put(json_in);

            Log("Unable to locate uid in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    j_uid = atoi(json_object_get_string(string_obj));

    /* gid */

    json_object_object_get_ex(json_in, "gid", &string_obj);

    if ( string_obj == NULL )
        {
            json_object_put(json_in);

            Log("Unable to locate gid in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    j_gid = atoi(json_object_get_string(string_obj));

    /* shell */

    json_object_object_get_ex(json_in, "shell", &string_obj);

    if ( string_obj == NULL )
        {
            json_object_put(json_in);

            Log("Unable to locate shell in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    result->pw_shell = malloc( MAX_SHELL_SIZE * sizeof(char *) );
    memset(result->pw_shell, 0, MAX_SHELL_SIZE);
    strlcpy( result->pw_shell, json_object_get_string(string_obj), MAX_SHELL_SIZE);

    /* home dir */

    json_object_object_get_ex(json_in, "home_dir", &string_obj);

    if ( string_obj == NULL )
        {
            json_object_put(json_in);

            Log("Unable to locate home_dir in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    result->pw_dir = malloc( MAX_HOME_DIR_SIZE * sizeof(char *) );
    memset(result->pw_dir, 0, MAX_HOME_DIR_SIZE);
    strlcpy( result->pw_dir, json_object_get_string(string_obj), MAX_HOME_DIR_SIZE);

    /* gecos */

    json_object_object_get_ex(json_in, "gecos", &string_obj);

    if ( string_obj == NULL )
        {
            json_object_put(json_in);

            Log("Unable to locate gecos in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    result->pw_gecos = malloc( MAX_GECOS_SIZE * sizeof(char *) );
    memset(result->pw_gecos, 0, MAX_GECOS_SIZE);
    strlcpy( result->pw_gecos, json_object_get_string(string_obj), MAX_GECOS_SIZE);

    /* legacy passwd placeholder */

    result->pw_passwd = malloc( 2 * sizeof(char *) );
    memset(result->pw_gecos, 0, 2);
    strlcpy( result->pw_passwd, "x", 2);

    result->pw_uid = j_uid;
    result->pw_gid = j_gid;

    json_object_put(json_in);

    if ( DEBUG_PASSWD == true )
        {
            printf("(_nss_k9_getpwent_r_locked) RETURN: |%s:%s:%d:%d:%s:%s:%s|\n", result->pw_name, result->pw_passwd, result->pw_uid, result->pw_gid, result->pw_gecos, result->pw_dir, result->pw_shell);
        }

    return NSS_STATUS_SUCCESS ;

}

