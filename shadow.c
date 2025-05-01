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
#include <pthread.h>

#include <nss.h>

#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <shadow.h>

#include "k9.h"

pthread_mutex_t GETSPNAM_R_MUTEX=PTHREAD_MUTEX_INITIALIZER;

enum nss_status _nss_k9_getspnam_r(const char *name, struct spwd *result, char *buffer, size_t buflen, int *errnop)
{

    pthread_mutex_lock(&GETSPNAM_R_MUTEX);

    enum nss_status ret;

    ret = _nss_k9_getspnam_r_locked(name, result, buffer, buflen, errnop);

    pthread_mutex_unlock(&GETSPNAM_R_MUTEX);

    return( ret );

}

