/*
 * Copyright (C) 2024-2025 Key9 Identity, Inc <k9.io>
 * Copyright (C) 2024-2025 Champ Clark III <cclark@k9.io>
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <yaml.h>

#include <nss.h>
#include <grp.h>
#include <pwd.h>
#include <shadow.h>

#include "k9.h"

/* Globals */

char API_KEY[DEFAULT_SIZE] = { 0 };

char QUERY_GROUP_NAME_URL[DEFAULT_SIZE] = { 0 };
char QUERY_GROUP_GID_URL[DEFAULT_SIZE] = { 0 };
char QUERY_GROUP_ID_URL[DEFAULT_SIZE] = { 0 };

char QUERY_PASSWD_USERNAME_URL[DEFAULT_SIZE] = { 0 };
char QUERY_PASSWD_UID_URL[DEFAULT_SIZE] = { 0 };
char QUERY_PASSWD_ID_URL[DEFAULT_SIZE] = { 0 };

char CONNECTION_TIMEOUT[CONNECTION_TIMEOUT_SIZE] = { 0 };

void Load_Config()
{

    yaml_parser_t parser;
    yaml_token_t token;

    int state = 0;

    char key[KEY_SIZE] = { 0 };
    char *value = NULL;

    char api_key[DEFAULT_SIZE] = { 0 };
    char company_uuid[DEFAULT_SIZE] = { 0 };

    FILE* fh = fopen( CONFIG_FILE, "r");

    if (fh == NULL)
        {
            Log("ERROR: Cannot open YAML file '%s'", CONFIG_FILE);
            exit(-1);
        }

    if (!yaml_parser_initialize(&parser))
        {
            Log("ERROR: Failed to initialize yaml parser!");
            exit(-1);
        }

    yaml_parser_set_input_file(&parser, fh);

    while (token.type != YAML_STREAM_END_TOKEN)
        {

            yaml_parser_scan(&parser, &token);

            switch(token.type)
                {

                case YAML_KEY_TOKEN:
                    state = 0;
                    break;

                case YAML_VALUE_TOKEN:
                    state = 1;
                    break;

                /* Since our configuration YAML is basic,  we don't bother processing
                   "blocks" */

                case YAML_SCALAR_TOKEN:

                    value = token.data.scalar.value;

                    if (state == 0 )
                        {
                            strlcpy(key, value, KEY_SIZE);
                        }
                    else
                        {

                            if ( !strcmp(key, "company_uuid" ))
                                {
                                    strlcpy( company_uuid, value, DEFAULT_SIZE );
                                }

                            else if ( !strcmp(key, "api_key" ))
                                {
                                    strlcpy( api_key, value, DEFAULT_SIZE );
                                }

                            else if ( !strcmp(key, "query_group_name" ))
                                {
                                    strlcpy(QUERY_GROUP_NAME_URL, value, DEFAULT_SIZE );
                                }

                            else if ( !strcmp(key, "query_group_gid" ))
                                {
                                    strlcpy(QUERY_GROUP_GID_URL, value, DEFAULT_SIZE );
                                }

                            else if ( !strcmp(key, "query_group_id" ))
                                {
                                    strlcpy(QUERY_GROUP_ID_URL, value, DEFAULT_SIZE );
                                }

                            else if ( !strcmp(key, "query_passwd_username" ))
                                {
                                    strlcpy(QUERY_PASSWD_USERNAME_URL, value, DEFAULT_SIZE );
                                }

                            else if ( !strcmp(key, "query_passwd_uid" ))
                                {
                                    strlcpy(QUERY_PASSWD_UID_URL, value, DEFAULT_SIZE );
                                }

                            else if ( !strcmp(key, "query_passwd_id" ))
                                {
                                    strlcpy(QUERY_PASSWD_ID_URL, value, DEFAULT_SIZE );
                                }

                            else if ( !strcmp(key, "connection_timeout" ))
                                {
                                    strlcpy(CONNECTION_TIMEOUT, value, CONNECTION_TIMEOUT_SIZE);
                                }

                        }

                default:

                    break;
                }
        }


    yaml_token_delete(&token);
    yaml_parser_delete(&parser);

    fclose(fh);

    /* Sanity Check */

    if ( company_uuid[0] == '\0' )
        {
            Log("ERROR: Cannot find 'company_uuid' in %s.", CONFIG_FILE);
            exit(-1);
        }

    if ( api_key[0] == '\0' )
        {
            Log("ERROR: Cannot find 'api_key' in %s.", CONFIG_FILE);
            exit(-1);
        }

    if ( QUERY_GROUP_NAME_URL[0] == '\0' )
        {
            Log("ERROR: Cannot find 'query_group_name' in %s.", CONFIG_FILE);
            exit(-1);
        }

    if ( QUERY_GROUP_GID_URL[0] == '\0' )
        {
            Log("ERROR: Cannot find 'query_group_gid' in %s.", CONFIG_FILE);
            exit(-1);
        }

    if ( QUERY_GROUP_ID_URL[0] == '\0' )
        {
            Log("ERROR: Cannot find 'query_group_id' in %s.", CONFIG_FILE);
            exit(-1);
        }

    if ( QUERY_PASSWD_USERNAME_URL[0] == '\0' )
        {
            Log("ERROR: Cannot find 'query_passwd_username' in %s.", CONFIG_FILE);
            exit(-1);
        }

    if ( QUERY_PASSWD_UID_URL[0] == '\0' )
        {
            Log("ERROR: Cannot find 'query_passwd_uid' in %s.", CONFIG_FILE);
            exit(-1);
        }

    if ( QUERY_PASSWD_ID_URL[0] == '\0' )
        {
            Log("ERROR: Cannot find 'query_passwd_id' in %s.", CONFIG_FILE);
            exit(-1);
        }

    /* Make full, usable API key */

    snprintf(API_KEY, sizeof(API_KEY), "%s:%s", company_uuid, api_key);
    API_KEY[ sizeof(API_KEY) - 1 ] = '\0';

}
