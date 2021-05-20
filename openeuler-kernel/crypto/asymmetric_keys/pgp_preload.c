// SPDX-License-Identifier: GPL-2.0
/* Cryptographic key request handling
 *
 * Copyright (C) 2011 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 *
 * See Documentation/security/keys-crypto.txt
 */

#include <linux/module.h>
#include <linux/key.h>
#include <linux/pgplib.h>
#include <linux/pgp.h>
#include <linux/err.h>
#include <keys/asymmetric-type.h>

struct preload_pgp_keys_context {
	struct pgp_parse_context pgp;
	key_ref_t keyring;
	const u8 *key_start;
	const u8 *key_end;
	bool found_key;
};

/*
 * Create a key.
 */
static int __init create_pgp_key(struct preload_pgp_keys_context *ctx)
{
	key_ref_t key;

	key = key_create_or_update(ctx->keyring,
				   "asymmetric",
				   NULL,
				   ctx->key_start,
				   ctx->key_end - ctx->key_start,
				   ((KEY_POS_ALL & ~KEY_POS_SETATTR) |
				    KEY_USR_VIEW | KEY_USR_READ),
				   KEY_ALLOC_NOT_IN_QUOTA |
				   KEY_ALLOC_BUILT_IN |
				   KEY_ALLOC_BYPASS_RESTRICTION);
	if (IS_ERR(key))
		return PTR_ERR(key);

	pr_notice("Loaded PGP key '%s'\n",
		  key_ref_to_ptr(key)->description);

	key_ref_put(key);
	return 0;
}

/*
 * Extract a public key or subkey from the PGP stream.
 */
static int __init found_pgp_key(struct pgp_parse_context *context,
				enum pgp_packet_tag type, u8 headerlen,
				const u8 *data, size_t datalen)
{
	struct preload_pgp_keys_context *ctx =
		container_of(context, struct preload_pgp_keys_context, pgp);
	int ret;

	if (ctx->found_key) {
		ctx->key_end = data - headerlen;
		ret = create_pgp_key(ctx);
		if (ret < 0)
			return ret;
	}

	ctx->key_start = data - headerlen;
	ctx->found_key = true;
	return 0;
}

/**
 * preload_pgp_keys - Load keys from a PGP keyring blob
 * @pgpdata: The PGP keyring blob containing the keys.
 * @pgpdatalen: The size of the @pgpdata blob.
 * @keyring: The keyring to add the new keys to.
 *
 * Preload a pack of keys from a PGP keyring blob.
 *
 * The keys have their descriptions generated from the user ID and fingerprint
 * in the PGP stream.  Since keys can be matched on their key IDs independently
 * of the key description, the description is mostly irrelevant apart from the
 * fact that keys of the same description displace one another from a keyring.
 *
 * The caller should override the current creds if they want the keys to be
 * owned by someone other than the current process's owner.  Keys will not be
 * accounted towards the owner's quota.
 *
 * This function may only be called whilst the kernel is booting.
 */
int __init preload_pgp_keys(const u8 *pgpdata, size_t pgpdatalen,
			    struct key *keyring)
{
	struct preload_pgp_keys_context ctx;
	int ret;

	ctx.pgp.types_of_interest = (1 << PGP_PKT_PUBLIC_KEY);
	ctx.pgp.process_packet = found_pgp_key;
	ctx.keyring = make_key_ref(keyring, 1);
	ctx.found_key = false;

	ret = pgp_parse_packets(pgpdata, pgpdatalen, &ctx.pgp);
	if (ret < 0)
		return ret;

	if (ctx.found_key) {
		ctx.key_end = pgpdata + pgpdatalen;
		return create_pgp_key(&ctx);
	}
	return 0;
}
