/* SPDX-License-Identifier: GPL-2.0 */
/* PGP library definitions (RFC 4880)
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#ifndef _LINUX_PGPLIB_H
#define _LINUX_PGPLIB_H

#if IS_ENABLED(CONFIG_PGP_LIBRARY) || IS_ENABLED(CONFIG_PGP_LIBRARY_MODULE)

#include <linux/pgp.h>

/*
 * PGP library packet parser
 */
struct pgp_parse_context {
	u64 types_of_interest;
	int (*process_packet)(struct pgp_parse_context *context,
			      enum pgp_packet_tag type,
			      u8 headerlen,
			      const u8 *data,
			      size_t datalen);
};

extern int pgp_parse_packets(const u8 *data, size_t datalen,
			     struct pgp_parse_context *ctx);

struct pgp_parse_pubkey {
	enum pgp_key_version version : 8;
	enum pgp_pubkey_algo pubkey_algo : 8;
	__kernel_old_time_t creation_time;
	__kernel_old_time_t expires_at;
};

extern int pgp_parse_public_key(const u8 **_data, size_t *_datalen,
				struct pgp_parse_pubkey *pk);


#endif /* CONFIG_PGP_LIBRARY */

#endif /* _LINUX_PGPLIB_H */
