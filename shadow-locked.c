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

extern char **environ;

enum nss_status _nss_k9_getspnam_r_locked(const char *name, struct spwd *result, char *buffer, size_t buflen, int *errnop)
{

    /* Return back a bogus record. */

    result->sp_namp = (char*)name;
    result->sp_pwdp = (char*)"*";

    return NSS_STATUS_SUCCESS;

}
