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

#define 	CONFIG_FILE "/opt/k9/etc/k9.yaml"

#define 	KEY_SIZE 	32
#define 	DEFAULT_SIZE 	512
#define		MAX_GROUP_SIZE	32768
#define		MAX_GROUP_NAME  64

#define 	MAX_LOG_SIZE 	1024
#define		USER_AGENT	"Key9 NSS"

#define		MAX_USERNAME_SIZE	256
#define		MAX_HOME_DIR_SIZE	256
#define		MAX_GECOS_SIZE		256
#define		MAX_SHELL_SIZE		64


//#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
//#endif

char *Query_K9( const char *url );
void Log (const char *format,... );
void Load_Config( void );

/* Passwd */

enum nss_status _nss_k9_getpwnam_r_locked(const char *name, struct passwd *result, char *buffer, size_t buflen, int *errnop);
enum nss_status _nss_k9_getpwuid_r_locked(uid_t uid, struct passwd *result, char *buffer, size_t buflen, int *errnop);
enum nss_status _nss_k9_getpwent_r_locked(struct passwd *result, char *buffer, size_t buflen, int *errnop);

/* Group */

enum nss_status _nss_k9_getgrgid_r_locked(gid_t gid, struct group *result, char *buffer, size_t buflen, int *errnop);
enum nss_status _nss_k9_getgrnam_r_locked(const char *name, struct group *result, char *buffer, size_t buflen, int *errnop);
enum nss_status _nss_k9_getgrent_r_locked(struct group *result, char *buffer, size_t buflen, int *errnop);

/* Shadow */

enum nss_status _nss_k9_getspnam_r_locked(const char *name, struct spwd *result, char *buffer, size_t buflen, int *errnop);

