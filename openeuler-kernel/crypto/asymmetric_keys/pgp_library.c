// SPDX-License-Identifier: GPL-2.0
/* PGP packet parser (RFC 4880)
 *
 * Copyright (C) 2011 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define pr_fmt(fmt) "PGPL: "fmt
#include <linux/pgplib.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");

const char *const pgp_hash_algorithms[PGP_HASH__LAST] = {
	[PGP_HASH_MD5]			= "md5",
	[PGP_HASH_SHA1]			= "sha1",
	[PGP_HASH_RIPE_MD_160]		= "rmd160",
	[PGP_HASH_SHA256]		= "sha256",
	[PGP_HASH_SHA384]		= "sha384",
	[PGP_HASH_SHA512]		= "sha512",
	[PGP_HASH_SHA224]		= "sha224",
};
EXPORT_SYMBOL_GPL(pgp_hash_algorithms);

const char *pgp_to_public_key_algo[PGP_PUBKEY__LAST] = {
	[PGP_PUBKEY_RSA_ENC_OR_SIG]	= "rsa",
	[PGP_PUBKEY_RSA_ENC_ONLY]	= "rsa",
	[PGP_PUBKEY_RSA_SIG_ONLY]	= "rsa",
	[PGP_PUBKEY_ELGAMAL]		= NULL,
	[PGP_PUBKEY_DSA]		= NULL,
};
EXPORT_SYMBOL_GPL(pgp_to_public_key_algo);

/**
 * pgp_parse_packet_header - Parse a PGP packet header
 * @_data: Start of the PGP packet (updated to PGP packet data)
 * @_datalen: Amount of data remaining in buffer (decreased)
 * @_type: Where the packet type will be returned
 * @_headerlen: Where the header length will be returned
 *
 * Parse a set of PGP packet header [RFC 4880: 4.2].
 *
 * Returns packet data size on success; non-zero on error.  If successful,
 * *_data and *_datalen will have been updated and *_headerlen will be set to
 * hold the length of the packet header.
 */
static ssize_t pgp_parse_packet_header(const u8 **_data, size_t *_datalen,
				       enum pgp_packet_tag *_type,
				       u8 *_headerlen)
{
	enum pgp_packet_tag type;
	const u8 *data = *_data;
	size_t size, datalen = *_datalen;

	pr_devel("-->%s(,%zu,,)\n", __func__, datalen);

	if (datalen < 2)
		goto short_packet;

	pr_devel("pkthdr %02x, %02x\n", data[0], data[1]);

	type = *data++;
	datalen--;
	if (!(type & 0x80)) {
		pr_debug("Packet type does not have MSB set\n");
		return -EBADMSG;
	}
	type &= ~0x80;

	if (type & 0x40) {
		/* New packet length format */
		type &= ~0x40;
		pr_devel("new format: t=%u\n", type);
		switch (data[0]) {
		case 0x00 ... 0xbf:
			/* One-byte length */
			size = data[0];
			data++;
			datalen--;
			*_headerlen = 2;
			break;
		case 0xc0 ... 0xdf:
			/* Two-byte length */
			if (datalen < 2)
				goto short_packet;
			size = (data[0] - 192) * 256;
			size += data[1] + 192;
			data += 2;
			datalen -= 2;
			*_headerlen = 3;
			break;
		case 0xff:
			/* Five-byte length */
			if (datalen < 5)
				goto short_packet;
			size =  data[1] << 24;
			size |= data[2] << 16;
			size |= data[3] << 8;
			size |= data[4];
			data += 5;
			datalen -= 5;
			*_headerlen = 6;
			break;
		default:
			pr_debug("Partial body length packet not supported\n");
			return -EBADMSG;
		}
	} else {
		/* Old packet length format */
		u8 length_type = type & 0x03;

		type >>= 2;
		pr_devel("old format: t=%u lt=%u\n", type, length_type);

		switch (length_type) {
		case 0:
			/* One-byte length */
			size = data[0];
			data++;
			datalen--;
			*_headerlen = 2;
			break;
		case 1:
			/* Two-byte length */
			if (datalen < 2)
				goto short_packet;
			size  = data[0] << 8;
			size |= data[1];
			data += 2;
			datalen -= 2;
			*_headerlen = 3;
			break;
		case 2:
			/* Four-byte length */
			if (datalen < 4)
				goto short_packet;
			size  = data[0] << 24;
			size |= data[1] << 16;
			size |= data[2] << 8;
			size |= data[3];
			data += 4;
			datalen -= 4;
			*_headerlen = 5;
			break;
		default:
			pr_debug("Indefinite length packet not supported\n");
			return -EBADMSG;
		}
	}

	pr_devel("datalen=%zu size=%zu", datalen, size);
	if (datalen < size)
		goto short_packet;
	if ((int)size < 0)
		goto too_big;

	*_data = data;
	*_datalen = datalen;
	*_type = type;
	pr_devel("Found packet type=%u size=%zd\n", type, size);
	return size;

short_packet:
	pr_debug("Attempt to parse short packet\n");
	return -EBADMSG;
too_big:
	pr_debug("Signature subpacket size >2G\n");
	return -EMSGSIZE;
}

/**
 * pgp_parse_packets - Parse a set of PGP packets
 * @_data: Data to be parsed (updated)
 * @_datalen: Amount of data (updated)
 * @ctx: Parsing context
 *
 * Parse a set of PGP packets [RFC 4880: 4].
 */
int pgp_parse_packets(const u8 *data, size_t datalen,
		      struct pgp_parse_context *ctx)
{
	enum pgp_packet_tag type;
	ssize_t pktlen;
	u8 headerlen;
	int ret;

	while (datalen > 2) {
		pktlen = pgp_parse_packet_header(&data, &datalen, &type,
						 &headerlen);
		if (pktlen < 0)
			return pktlen;

		if ((ctx->types_of_interest >> type) & 1) {
			ret = ctx->process_packet(ctx, type, headerlen,
						  data, pktlen);
			if (ret < 0)
				return ret;
		}
		data += pktlen;
		datalen -= pktlen;
	}

	if (datalen != 0) {
		pr_debug("Excess octets in packet stream\n");
		return -EBADMSG;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(pgp_parse_packets);

/**
 * pgp_parse_public_key - Parse the common part of a PGP pubkey packet
 * @_data: Content of packet (updated)
 * @_datalen: Length of packet remaining (updated)
 * @pk: Public key data
 *
 * Parse the common data struct for a PGP pubkey packet [RFC 4880: 5.5.2].
 */
int pgp_parse_public_key(const u8 **_data, size_t *_datalen,
			 struct pgp_parse_pubkey *pk)
{
	const u8 *data = *_data;
	size_t datalen = *_datalen;
	unsigned int tmp;

	if (datalen < 12) {
		pr_debug("Public key packet too short\n");
		return -EBADMSG;
	}

	pk->version = *data++;
	switch (pk->version) {
	case PGP_KEY_VERSION_2:
	case PGP_KEY_VERSION_3:
	case PGP_KEY_VERSION_4:
		break;
	default:
		pr_debug("Public key packet with unhandled version %d\n",
			   pk->version);
		return -EBADMSG;
	}

	tmp  = *data++ << 24;
	tmp |= *data++ << 16;
	tmp |= *data++ << 8;
	tmp |= *data++;
	pk->creation_time = tmp;
	if (pk->version == PGP_KEY_VERSION_4) {
		pk->expires_at = 0; /* Have to get it from the selfsignature */
	} else {
		unsigned short ndays;

		ndays  = *data++ << 8;
		ndays |= *data++;
		if (ndays)
			pk->expires_at = pk->creation_time + ndays * 86400UL;
		else
			pk->expires_at = 0;
		datalen -= 2;
	}

	pk->pubkey_algo = *data++;
	datalen -= 6;

	pr_devel("%x,%x,%lx,%lx\n",
		 pk->version, pk->pubkey_algo, pk->creation_time,
		 pk->expires_at);

	*_data = data;
	*_datalen = datalen;
	return 0;
}
EXPORT_SYMBOL_GPL(pgp_parse_public_key);
