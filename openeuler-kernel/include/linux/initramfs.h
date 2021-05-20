/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/initramfs.h
 *
 * Include file for file metadata in the initial ram disk.
 */
#ifndef _LINUX_INITRAMFS_H
#define _LINUX_INITRAMFS_H

#define METADATA_FILENAME "METADATA!!!"

enum metadata_types { TYPE_NONE, TYPE_XATTR, TYPE__LAST };

struct metadata_hdr {
	char c_size[8];     /* total size including c_size field */
	char c_version;     /* header version */
	char c_type;        /* metadata type */
	char c_metadata[];  /* metadata */
} __packed;

#endif /*LINUX_INITRAMFS_H*/
