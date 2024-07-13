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

#include <nss.h>
#include <grp.h>
#include <pwd.h>
#include <shadow.h>

#include <string.h>

#include <curl/curl.h>
#include <json-c/json.h>

#include "k9.h"

extern char QUERY_GROUP_NAME_URL[DEFAULT_SIZE];
extern char QUERY_GROUP_GID_URL[DEFAULT_SIZE];
extern char QUERY_GROUP_ID_URL[DEFAULT_SIZE];


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

    Load_Config();

    char lookup_url[8192] = { 0 };

    snprintf(lookup_url, sizeof(lookup_url), "%s/%s", QUERY_GROUP_NAME_URL, name);
    lookup_url[ sizeof(lookup_url) - 1 ] = '\0';

    response = Query_K9( lookup_url );

    if ( response == NULL )
        {
            Log("Group name %s not found.", name);
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


    /* group */

    json_object_object_get_ex(json_in, "group", &string_obj);

    if ( string_obj == NULL )
        {
            json_object_put(json_in);

            Log("Unable to locate group in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    result->gr_name = malloc( MAX_GROUP_SIZE * sizeof(char *) );
    strlcpy( result->gr_name, json_object_get_string(string_obj), MAX_GROUP_SIZE);

    /* group */

    json_object_object_get_ex(json_in, "gid", &string_obj);

    if ( string_obj == NULL )
        {
            json_object_put(json_in);

            Log("Unable to locate gid in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    j_gid = atoi(json_object_get_string(string_obj));

    /* members */

    json_object_object_get_ex(json_in, "members", &string_obj);

    if ( string_obj == NULL )
        {
            json_object_put(json_in);

            Log("Unable to locate members in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    j_members = json_object_get_string(string_obj);

    /* Stuff "members" into an array */

    result->gr_passwd = "x";
    result->gr_gid = j_gid;

    /* Stuff "members" into an array */

    strlcpy(tmp, j_members, sizeof(tmp));
    members_ptr = strtok_r( tmp, ",", &token);

    while (members_ptr != NULL )
        {

            result->gr_mem[i] = members_ptr;
            result->gr_mem[i+1] = NULL;

            members_ptr = strtok_r(NULL, ",", &token);
            i++;

        }

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

    Load_Config();

    char lookup_url[8192] = { 0 };

    snprintf(lookup_url, sizeof(lookup_url), "%s/%d", QUERY_GROUP_GID_URL, gid);
    lookup_url[ sizeof(lookup_url) - 1 ] = '\0';

    response = Query_K9( lookup_url );

    if ( response == NULL )
        {
            Log("GID %d not found.", gid);
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


    /* group */

    json_object_object_get_ex(json_in, "group", &string_obj);

    if ( string_obj == NULL )
        {
            json_object_put(json_in);

            Log("Unable to locate group in JSON");
            return NSS_STATUS_UNAVAIL;
        }

     result->gr_name = malloc( MAX_GROUP_SIZE * sizeof(char *) );
     strlcpy( result->gr_name, json_object_get_string(string_obj), MAX_GROUP_SIZE );

    /* gid */

    json_object_object_get_ex(json_in, "gid", &string_obj);

    if ( string_obj == NULL )
        {
            json_object_put(json_in);

            Log("Unable to locate gid in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    j_gid = atoi(json_object_get_string(string_obj));

    /* members */

    json_object_object_get_ex(json_in, "members", &string_obj);

    if ( string_obj == NULL )
        {
            json_object_put(json_in);

            Log("Unable to locate members in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    j_members = json_object_get_string(string_obj);

    /* Stuff "members" into an array */

    result->gr_passwd = "x";
    result->gr_gid = j_gid;

    /* Stuff "members" into an array */

    strlcpy(tmp, j_members, sizeof(tmp));
    members_ptr = strtok_r( tmp, ",", &token);

    while (members_ptr != NULL )
        {

            result->gr_mem[i] = members_ptr;
            result->gr_mem[i+1] = NULL;

            members_ptr = strtok_r(NULL, ",", &token);
            i++;

        }

    json_object_put(json_in);

    return NSS_STATUS_SUCCESS ;

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
    int a = 0;
    int cc = 1; 			/* Comma count */

    struct json_object *json_in = NULL;
    json_object *string_obj;

    Load_Config();

    static int u = 0;
    u++;

    snprintf(lookup_url, sizeof(lookup_url), "%s/%d", QUERY_GROUP_ID_URL, u);
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
            return NSS_STATUS_UNAVAIL;
        }

    /* group */

    json_object_object_get_ex(json_in, "group", &string_obj);

    if ( string_obj == NULL )
        {
            json_object_put(json_in);

            Log("Unable to locate group in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    result->gr_name = malloc( MAX_GROUP_SIZE * sizeof(char *) );
    strlcpy( result->gr_name, json_object_get_string(string_obj), MAX_GROUP_SIZE );

    /* gid */

    json_object_object_get_ex(json_in, "gid", &string_obj);

    if ( string_obj == NULL )
        {
            json_object_put(json_in);

            Log("Unable to locate gid in JSON");
            return NSS_STATUS_NOTFOUND;
        }

    j_gid = atoi(json_object_get_string(string_obj));

    /* members */

    json_object_object_get_ex(json_in, "members", &string_obj);

    if ( string_obj == NULL )
        {
            json_object_put(json_in);

            Log("Unable to locate members in JSON");
            return NSS_STATUS_UNAVAIL;
        }

    j_members = json_object_get_string(string_obj);

    /* Stuff "members" into an array */
    
    result->gr_passwd = "x";
    result->gr_gid = j_gid;

    /* Get the number of commas */

    for ( a = 0; a < strlen(j_members); a++ )
        {
            if ( j_members[a] == ',' )
                {
                    cc++;
                }
        }

    /* Allocate memory for gr_mem */

    result->gr_mem = malloc( ( MAX_GROUP_NAME * cc ) * sizeof(char* ) );

    for (a = 0; a < cc; a++)
        {
            result->gr_mem[a] = malloc( MAX_GROUP_NAME * sizeof(char *) );
        }

    /* Stuff "members" into an array */

    strlcpy(tmp, j_members, sizeof(tmp));

    members_ptr = strtok_r(tmp, ",", &token);

    while (members_ptr != NULL )
        {

            result->gr_mem[i] = members_ptr;
            result->gr_mem[i+1] = NULL;

            members_ptr = strtok_r(NULL, ",", &token);
            i++;

        }

    json_object_put(json_in);

    return NSS_STATUS_SUCCESS;

}

