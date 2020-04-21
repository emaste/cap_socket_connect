/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 The FreeBSD Foundation
 *
 * This software was developed by Tiger Gao under sponsorship from
 * the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
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

#include <err.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libcasper.h>
#include <libcasper_service.h>

#include "cap_socket.h"

static nvlist_t *
parse_and_store_args(const char *dest)
{
	char *args[3];
	int j;
	const int len = strlen(dest) + 1;
	char *token;
	nvlist_t *nvl;

	j = 0;
	char buf[len];
	nvl = nvlist_create(0);
	strncpy(buf, dest, len);
	token = strtok(buf, ":");
	while (token) {
		args[j++] = token;
		token = strtok(NULL, ":");
	}
	if (j == 3) {
		nvlist_add_string(nvl, "type", args[0]);
		nvlist_add_string(nvl, "hostname", args[1]);
		nvlist_add_string(nvl, "port", args[2]);
	} else {
		fprintf(stderr, "%s", "Format error. \n");
		return (NULL);
	}

	return nvl;
}

int 
cap_socket_init(cap_channel_t *chan, int count, const char **allowed_dests)
{
	nvlist_t *limits, *nvl;
	nvlist_t *arr[count];
	int i;

	limits = nvlist_create(0);
	for(i = 0; i < count; i++) {
		/* dest is of format "tcp:127.0.0.1:8080", port can be set to any port
		   using sentinel value -1. If type is left empty it will be resolved
		   automatically eg. www.google.com:-1
		*/
		nvl = parse_and_store_args(allowed_dests[i]);
		if (!nvl) {
			err(1, "Wrong format: %s", allowed_dests[i]);
			return (-1);
		}
		arr[i] = nvl;
	}
	nvlist_add_nvlist_array(limits, "allowed_dests", 
	    (const struct nvlist *const *)arr, count);
	/* free memory */
	for(i = 0; i < count; i++)
		nvlist_destroy(arr[i]);
	if (cap_limit_set(chan, limits) < 0) {
		fprintf(stderr, "%s", "Cannot set limit. \n");
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
	const nvlist_t * const *allowed_dests;
	const nvlist_t *allowed_dest;
	nvlist_t *dest_args;
	const char *cause, *dest_host, *dest_type, *dest_port;
	struct addrinfo hints, *res, *res0;
	size_t nitems;
	int sock, error, type;
	unsigned int i;
	bool is_allowed;

	if (strcmp(cmd, "socket_connect") != 0)
		return (EINVAL);
	if (limits == NULL)
		return (ENOTCAPABLE);

	is_allowed = false;
	/* Parse and store current socket destination */
	dest_args = parse_and_store_args(nvlist_get_string(nvlin, "dest"));
	dest_host = nvlist_get_string(dest_args, "hostname");
	dest_type = nvlist_get_string(dest_args, "type");
	dest_port = nvlist_get_string(dest_args, "port");
	/* Check if dest in allowed set */
	allowed_dests = nvlist_get_nvlist_array(limits, "allowed_dests", &nitems);
	for(i = 0; i < nitems; i++) {
		allowed_dest = allowed_dests[i];
		if (strcmp(nvlist_get_string(allowed_dest, "hostname"), 
		    dest_host) == 0) {
				/* type and port must be allowed. If type is any or type is equal to
				   current type, then type is allowed. If port is -1 or port is equal
				   to current port, port is allowed.
				   */
				const char *allowed_type = nvlist_get_string(allowed_dest, "type");
				const char *allowed_port = nvlist_get_string(allowed_dest, "port");
				if (((strcmp(allowed_type, "any") == 0) ||
				    (strcmp(allowed_type, dest_type) == 0)) &&
					((strcmp(allowed_port, "-1") == 0) ||
				    (strcmp(allowed_port, dest_port) == 0)))
					is_allowed = true;
		}
	}
	if (!is_allowed)
		return (ENOTCAPABLE);
	/* initialize hints */
	memset(&hints, 0, sizeof(hints));
	/* Set socket type hint if type is specified. */
	type = -1;
	if (!strcmp(dest_type, "tcp") || !strcmp(dest_type, "TCP"))
		type = SOCK_STREAM;
	else if (!strcmp(dest_type, "udp") || !strcmp(dest_type, "UDP"))
		type = SOCK_DGRAM;
	else if (!strcmp(dest_type, "raw") || !strcmp(dest_type, "RAW"))
		type = SOCK_RAW;
	else if (!strcmp(dest_type, "rdm") || !strcmp(dest_type, "RDM"))
		type = SOCK_RDM;
	else if (!strcmp(dest_type, "seqpacket") || 
	    !strcmp(dest_type, "SEQPACKET"))
		type = SOCK_SEQPACKET;
	else {
		nvlist_add_string(nvlout, "errmsg", "Wrong socket type.\n");
		return (EINVAL);
	}
	if (type != -1)
		hints.ai_socktype = type;
	hints.ai_flags = AI_ALL;
	if (!strcmp(dest_port, "-1"))
		dest_port = NULL;
	error = getaddrinfo(dest_host, dest_port, &hints, &res0);
	if (error) {
		nvlist_add_string(nvlout, "errmsg", gai_strerror(error));
		return (EINVAL);
	}
	for (res = res0; res; res = res->ai_next) {
		sock = socket(res->ai_family, res->ai_socktype,
			res->ai_protocol);
		if (sock < 0) {
			cause = "socket\n";
			continue;
		}

		if (connect(sock, res->ai_addr,	res->ai_addrlen) < 0) {
			cause = "connect\n";
			close(sock);
			sock = -1;
			continue;
		}

		break;
	}
	if (sock < 0) {
		nvlist_add_string(nvlout, "errmsg", cause);
		return (EINVAL);
	}
	freeaddrinfo(res0);
	nvlist_move_descriptor(nvlout, "sockdesc", sock);
    return (0);
}

CREATE_SERVICE("system.socket", exec_limits, exec_command, 0);
