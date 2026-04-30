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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <syslog.h>

#include <curl/curl.h>

#include <nss.h>
#include <grp.h>
#include <pwd.h>
#include <shadow.h>

#include <stdbool.h>

#include "k9.h"

extern char API_KEY[DEFAULT_SIZE];

extern char QUERY_GROUP_NAME_URL[DEFAULT_SIZE];
extern char QUERY_GROUP_GID_URL[DEFAULT_SIZE];
extern char QUERY_GROUP_ID_URL[DEFAULT_SIZE];

extern char QUERY_PASSWD_USERNAME_URL[DEFAULT_SIZE];
extern char QUERY_PASSWD_UID_URL[DEFAULT_SIZE];
extern char QUERY_PASSWD_ID_URL[DEFAULT_SIZE];

extern char CONNECTION_TIMEOUT[CONNECTION_TIMEOUT_SIZE];

static CURL *curl_handle = NULL;

__attribute__((constructor))
static void k9_init(void)
{
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl_handle = curl_easy_init();
}

__attribute__((destructor))
static void k9_fini(void)
{
    curl_easy_cleanup(curl_handle);
    curl_global_cleanup();
}

/****************************************************************************
 * write_callback_func() - Callback for data received via libcurl
 ****************************************************************************/

size_t static write_callback_func(void *buffer, size_t size, size_t nmemb, void *userp)
{
    char **response_ptr =  (char**)userp;
    *response_ptr = strndup(buffer, (size_t)(size *nmemb));     /* Return the string */
    return size * nmemb;
}


char *Query_K9( const char *url )
{

    char tmp_api[512] = { 0 };

    CURLcode res;

    struct curl_slist *headers = NULL;
    char *response = NULL;

    if ( !curl_handle )
        {
            Log("Error: curl handle not initialized");
            return NULL;
        }

    snprintf(tmp_api, sizeof(tmp_api), "API_KEY: %s", API_KEY);
    tmp_api[ sizeof(tmp_api) - 1 ] = '\0';

    curl_easy_reset(curl_handle);

    curl_easy_setopt(curl_handle, CURLOPT_URL, url);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_callback_func);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL, 1);    /* Will send SIGALRM if not set */
    curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, atol(CONNECTION_TIMEOUT) );

    headers = curl_slist_append(headers, USER_AGENT);
    headers = curl_slist_append(headers, tmp_api);

    curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
    res = curl_easy_perform(curl_handle);

    curl_slist_free_all(headers);

    return( response );

}

void Log (const char *format,... )
{

    va_list ap;
    va_start(ap, format);
    char buf[MAX_LOG_SIZE] = { 0 };

    vsnprintf(buf, MAX_LOG_SIZE, format, ap);

    openlog("k9-nss", LOG_PID, LOG_DAEMON);
    syslog(LOG_INFO, "%s",  buf);
    closelog();

}
