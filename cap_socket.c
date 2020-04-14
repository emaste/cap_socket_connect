/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2020
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/capsicum.h>
#include <sys/dnv.h>
#include <sys/errno.h>
#include <sys/nv.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libcasper.h>
#include <libcasper_service.h>

#include "cap_socket.h"

int 
cap_socket_init(cap_channel_t *chan, int count, const char **allowed_dest)
{
	nvlist_t *limits;

	limits = nvlist_create(0);
	nvlist_add_string_array(limits, "allowed_dest", allowed_dest, count);
	if (cap_limit_set(chan, limits) < 0) {
		return (-1);
	}
	return (0);
}

int 
cap_socket_connect(cap_channel_t *chan, const char *dest) {
	nvlist_t *nvl;
	int error, sock;
	const char *errmsg;

	nvl = nvlist_create(0);
	nvlist_add_string(nvl, "cmd", "socket_connect");
	nvlist_add_string(nvl, "dest", dest);
	nvl = cap_xfer_nvlist(chan, nvl);
	if (nvl == NULL) {
		return (-1);
	}
	error = (int)dnvlist_get_number(nvl, "error", 0);
	if (error != 0)	{
		errno = error;
		if (nvlist_exists_string(nvl, "errmsg")) {
			errmsg = nvlist_get_string(nvl, "errmsg");
			fprintf(stderr, "%s", errmsg);
		}
		return (-1);
	}
	sock = dnvlist_take_descriptor(nvl, "sockdesc", -1);
	nvlist_destroy(nvl);
	return (sock);
}

static int
exec_limits(const nvlist_t *oldlimits, const nvlist_t *newlimits) 
{
	
	/* only allow limit to be set once */
	if (oldlimits != NULL)
		return (ENOTCAPABLE);
	(void) newlimits;
	return (0);
}

static int
exec_command(const char *cmd, const nvlist_t *limits, nvlist_t *nvlin,
    nvlist_t *nvlout) 
{
	const char * const *allowed_dest;
	char *buf;
	char dest[50], ip_addr[50];
	size_t nitems;
	int sock, type, portno;
	unsigned int i;
	struct sockaddr_in serv_addr; 
	bool is_allowed;

	if (strcmp(cmd, "socket_connect") != 0)
		return (EINVAL);
	if (limits == NULL)
		return (ENOTCAPABLE);

	is_allowed = false;
	allowed_dest = nvlist_get_string_array(limits, "allowed_dest", &nitems);
	strcpy(dest, nvlist_get_string(nvlin, "dest"));
	/* Check if dest addr in allowed set */
	for(i = 0; i < nitems; i++) {
		if (strcmp(allowed_dest[i], dest) == 0)
			is_allowed = true;
	}
	if (!is_allowed)
		return (ENOTCAPABLE);

	/* parse socket type, address, and port */
	buf = strtok(dest, ":");
	if (!strcmp(buf, "tcp") || !strcmp(buf, "TCP"))
		type = SOCK_STREAM;
	else if (!strcmp(buf, "udp") || !strcmp(buf, "UDP"))
		type = SOCK_DGRAM;
	else {
		nvlist_add_string(nvlout, "errmsg", "Please specify tcp or udp.\n");
		return (EINVAL);
	}
	if ((sock = socket(AF_INET, type, 0)) < 0) { 
        nvlist_add_string(nvlout, "errmsg", "Socket creation.\n");
		return (EINVAL);
    }
	buf = strtok(NULL, ":");
	strcpy(ip_addr, buf);
	buf = strtok(NULL, ":");
	portno = atoi(buf);
	serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(portno);
	if (inet_pton(AF_INET, ip_addr, &serv_addr.sin_addr) <= 0)  
    {
        nvlist_add_string(nvlout, "errmsg", 
		    "Invalid address/ Address not supported \n");
		return (EINVAL);
    }
   
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
    { 
        nvlist_add_string(nvlout, "errmsg", "Connection failed.\n");
		return (ECONNREFUSED);
    }
	nvlist_move_descriptor(nvlout, "sockdesc", sock);
    return (0);
}

CREATE_SERVICE("system.socket", exec_limits, exec_command, 0);
