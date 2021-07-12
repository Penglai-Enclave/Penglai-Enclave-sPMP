// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2005-2010 IBM Corporation
 *
 * Author:
 * Mimi Zohar <zohar@us.ibm.com>
 * Kylene Hall <kjhall@us.ibm.com>
 *
 * File: evm_main.c
 *	implements evm_inode_setxattr, evm_inode_post_setxattr,
 *	evm_inode_removexattr, and evm_verifyxattr
 */

#include <linux/init.h>
#include <linux/crypto.h>
#include <linux/audit.h>
#include <linux/xattr.h>
#include <linux/integrity.h>
#include <linux/evm.h>
#include <linux/magic.h>
#include <linux/posix_acl_xattr.h>

#include <crypto/hash.h>
#include <crypto/hash_info.h>
#include <crypto/algapi.h>
#include "evm.h"

int evm_initialized;

static const char * const integrity_status_msg[] = {
	"pass", "pass_immutable", "fail", "fail_immutable", "no_label",
	"no_xattrs", "unknown"
};
int evm_hmac_attrs;

static struct xattr_list evm_config_default_xattrnames[] = {
#ifdef CONFIG_SECURITY_SELINUX
	{.name = XATTR_NAME_SELINUX},
#endif
#ifdef CONFIG_SECURITY_SMACK
	{.name = XATTR_NAME_SMACK},
#ifdef CONFIG_EVM_EXTRA_SMACK_XATTRS
	{.name = XATTR_NAME_SMACKEXEC},
	{.name = XATTR_NAME_SMACKTRANSMUTE},
	{.name = XATTR_NAME_SMACKMMAP},
#endif
#endif
#ifdef CONFIG_SECURITY_APPARMOR
	{.name = XATTR_NAME_APPARMOR},
#endif
#ifdef CONFIG_IMA_APPRAISE
	{.name = XATTR_NAME_IMA},
#endif
	{.name = XATTR_NAME_CAPS},
};

LIST_HEAD(evm_config_xattrnames);

static int evm_fixmode;
static int __init evm_set_param(char *str)
{
	if (strncmp(str, "fix", 3) == 0)
		evm_fixmode = 1;
	else if (strncmp(str, "x509", 4) == 0)
		evm_initialized |= EVM_INIT_X509;
	else if (strncmp(str, "allow_metadata_writes", 21) == 0)
		evm_initialized |= EVM_ALLOW_METADATA_WRITES;
	else if (strncmp(str, "complete", 8) == 0)
		evm_initialized |= EVM_SETUP_COMPLETE;
	else
		pr_err("invalid \"%s\" mode", str);

	return 0;
}
__setup("evm=", evm_set_param);

static void __init evm_init_config(void)
{
	int i, xattrs;

	xattrs = ARRAY_SIZE(evm_config_default_xattrnames);

	pr_info("Initialising EVM extended attributes:\n");
	for (i = 0; i < xattrs; i++) {
		pr_info("%s\n", evm_config_default_xattrnames[i].name);
		list_add_tail(&evm_config_default_xattrnames[i].list,
			      &evm_config_xattrnames);
	}

#ifdef CONFIG_EVM_ATTR_FSUUID
	evm_hmac_attrs |= EVM_ATTR_FSUUID;
#endif
	pr_info("HMAC attrs: 0x%x\n", evm_hmac_attrs);
}

static bool evm_key_loaded(void)
{
	return (bool)(evm_initialized & EVM_KEY_MASK);
}

/*
 * Ignoring INTEGRITY_NOLABEL/INTEGRITY_NOXATTRS is safe if no HMAC key
 * is loaded and the EVM_SETUP_COMPLETE initialization flag is set.
 */
static bool evm_ignore_error_safe(enum integrity_status evm_status)
{
	if (evm_initialized & EVM_INIT_HMAC)
		return false;

	if (!(evm_initialized & EVM_SETUP_COMPLETE))
		return false;

	if (evm_status != INTEGRITY_NOLABEL && evm_status != INTEGRITY_NOXATTRS)
		return false;

	return true;
}

static int evm_find_protected_xattrs(struct dentry *dentry, int *ima_present)
{
	struct inode *inode = d_backing_inode(dentry);
	struct xattr_list *xattr;
	int error;
	int count = 0;

	if (!(inode->i_opflags & IOP_XATTR))
		return -EOPNOTSUPP;

	list_for_each_entry_lockless(xattr, &evm_config_xattrnames, list) {
		error = __vfs_getxattr(dentry, inode, xattr->name, NULL, 0);
		if (error < 0) {
			if (error == -ENODATA)
				continue;
			return error;
		}
		if (!strcmp(xattr->name, XATTR_NAME_IMA))
			*ima_present = 1;
		count++;
	}

	return count;
}

/*
 * evm_verify_hmac - calculate and compare the HMAC with the EVM xattr
 *
 * Compute the HMAC on the dentry's protected set of extended attributes
 * and compare it against the stored security.evm xattr.
 *
 * For performance:
 * - use the previoulsy retrieved xattr value and length to calculate the
 *   HMAC.)
 * - cache the verification result in the iint, when available.
 *
 * Returns integrity status
 */
static enum integrity_status evm_verify_hmac(struct dentry *dentry,
					     const char *xattr_name,
					     char *xattr_value,
					     size_t xattr_value_len,
					     struct integrity_iint_cache *iint)
{
	struct evm_ima_xattr_data *xattr_data = NULL;
	struct signature_v2_hdr *hdr;
	enum integrity_status evm_status = INTEGRITY_PASS;
	enum integrity_status saved_evm_status = INTEGRITY_UNKNOWN;
	struct evm_digest digest;
	struct ima_digest *found_digest;
	struct inode *inode;
	struct signature_v2_hdr evm_fake_xattr = {
				.type = EVM_IMA_XATTR_DIGEST_LIST,
				.version = 2, .hash_algo = HASH_ALGO_SHA256 };
	int rc, xattr_len, evm_immutable = 0, ima_present = 0;

	if (iint && (iint->evm_status == INTEGRITY_PASS ||
		     iint->evm_status == INTEGRITY_PASS_IMMUTABLE))
		return iint->evm_status;

	/* if status is not PASS, try to check again - against -ENOMEM */

	/* first need to know the sig type */
	rc = vfs_getxattr_alloc(dentry, XATTR_NAME_EVM, (char **)&xattr_data, 0,
				GFP_NOFS);
	if (rc <= 0) {
		evm_status = INTEGRITY_FAIL;
		if (rc == -ENODATA) {
			rc = evm_find_protected_xattrs(dentry, &ima_present);
			if (rc > 0)
				evm_status = INTEGRITY_NOLABEL;
			else if (rc == 0)
				evm_status = INTEGRITY_NOXATTRS; /* new file */
		} else if (rc == -EOPNOTSUPP) {
			evm_status = INTEGRITY_UNKNOWN;
		}
		/* IMA added a fake xattr, set also EVM fake xattr */
		if (!ima_present && xattr_name &&
		    !strcmp(xattr_name, XATTR_NAME_IMA) &&
		    xattr_value_len > 2) {
			evm_fake_xattr.hash_algo =
			  ((struct evm_ima_xattr_data *)xattr_value)->data[0];
			xattr_data =
			  (struct evm_ima_xattr_data *)&evm_fake_xattr;
			rc = sizeof(evm_fake_xattr);
		}
		if (xattr_data != (struct evm_ima_xattr_data *)&evm_fake_xattr)
			goto out;

		saved_evm_status = evm_status;
	}

	xattr_len = rc;

	/* check value type */
	switch (xattr_data->type) {
	case EVM_XATTR_HMAC:
		if (xattr_len != hash_digest_size[evm_hash_algo] + 1) {
			evm_status = INTEGRITY_FAIL;
			goto out;
		}
		digest.hdr.algo = evm_hash_algo;
		rc = evm_calc_hmac(dentry, xattr_name, xattr_value,
				   xattr_value_len, &digest);
		if (rc)
			break;
		rc = crypto_memneq(xattr_data->data, digest.digest,
				   hash_digest_size[evm_hash_algo]);
		if (rc)
			rc = -EINVAL;
		break;
	case EVM_XATTR_PORTABLE_DIGSIG:
		evm_immutable = 1;
		fallthrough;
	case EVM_IMA_XATTR_DIGSIG:
		/* accept xattr with non-empty signature field */
		if (xattr_len <= sizeof(struct signature_v2_hdr)) {
			evm_status = INTEGRITY_FAIL;
			goto out;
		}

		hdr = (struct signature_v2_hdr *)xattr_data;
		digest.hdr.algo = hdr->hash_algo;
		rc = evm_calc_hash(dentry, xattr_name, xattr_value,
				   xattr_value_len, xattr_data->type, &digest);
		if (rc)
			break;
		rc = integrity_digsig_verify(INTEGRITY_KEYRING_EVM,
					(const char *)xattr_data, xattr_len,
					digest.digest, digest.hdr.length);
		if (!rc) {
			inode = d_backing_inode(dentry);

			if (xattr_data->type == EVM_XATTR_PORTABLE_DIGSIG) {
				if (iint)
					iint->flags |= EVM_IMMUTABLE_DIGSIG;
				evm_status = INTEGRITY_PASS_IMMUTABLE;
			} else if (!IS_RDONLY(inode) &&
				   !(inode->i_sb->s_readonly_remount) &&
				   !IS_IMMUTABLE(inode)) {
				evm_update_evmxattr(dentry, xattr_name,
						    xattr_value,
						    xattr_value_len);
			}
		}
		break;
	case EVM_IMA_XATTR_DIGEST_LIST:
		/* At this point, we cannot determine whether metadata are
		 * immutable or not. However, it is safe to return the
		 * fail_immutable error, as HMAC will not be created for this
		 * security.evm type.
		 */
		evm_immutable = 1;

		if (xattr_len < offsetof(struct signature_v2_hdr, keyid)) {
			evm_status = INTEGRITY_FAIL;
			goto out;
		}

		hdr = (struct signature_v2_hdr *)xattr_data;
		digest.hdr.algo = hdr->hash_algo;
		rc = evm_calc_hash(dentry, xattr_name, xattr_value,
				   xattr_value_len, xattr_data->type, &digest);
		if (rc)
			break;

		found_digest = ima_lookup_digest(digest.digest, hdr->hash_algo,
						 COMPACT_METADATA);
		if (!found_digest) {
			rc = -ENOENT;
			break;
		}

		if (!ima_digest_allow(found_digest, IMA_APPRAISE)) {
			rc = -EACCES;
			break;
		}

		if (ima_digest_is_immutable(found_digest)) {
			if (iint)
				iint->flags |= EVM_IMMUTABLE_DIGSIG;
			evm_status = INTEGRITY_PASS_IMMUTABLE;
		} else {
			evm_status = INTEGRITY_PASS;
		}
		break;
	default:
		rc = -EINVAL;
		break;
	}

	if (rc && xattr_data == (struct evm_ima_xattr_data *)&evm_fake_xattr) {
		evm_status = saved_evm_status;
	} else if (rc) {
		evm_status = INTEGRITY_NOXATTRS;
		if (rc != -ENODATA)
			evm_status = evm_immutable ?
				     INTEGRITY_FAIL_IMMUTABLE : INTEGRITY_FAIL;
	}
out:
	if (iint)
		iint->evm_status = evm_status;
	if (xattr_data != (struct evm_ima_xattr_data *)&evm_fake_xattr)
		kfree(xattr_data);
	return evm_status;
}

static int evm_protected_xattr(const char *req_xattr_name)
{
	int namelen;
	int found = 0;
	struct xattr_list *xattr;

	namelen = strlen(req_xattr_name);
	list_for_each_entry_lockless(xattr, &evm_config_xattrnames, list) {
		if ((strlen(xattr->name) == namelen)
		    && (strncmp(req_xattr_name, xattr->name, namelen) == 0)) {
			found = 1;
			break;
		}
		if (strncmp(req_xattr_name,
			    xattr->name + XATTR_SECURITY_PREFIX_LEN,
			    strlen(req_xattr_name)) == 0) {
			found = 1;
			break;
		}
	}

	return found;
}

/**
 * evm_verifyxattr - verify the integrity of the requested xattr
 * @dentry: object of the verify xattr
 * @xattr_name: requested xattr
 * @xattr_value: requested xattr value
 * @xattr_value_len: requested xattr value length
 *
 * Calculate the HMAC for the given dentry and verify it against the stored
 * security.evm xattr. For performance, use the xattr value and length
 * previously retrieved to calculate the HMAC.
 *
 * Returns the xattr integrity status.
 *
 * This function requires the caller to lock the inode's i_mutex before it
 * is executed.
 */
enum integrity_status evm_verifyxattr(struct dentry *dentry,
				      const char *xattr_name,
				      void *xattr_value, size_t xattr_value_len,
				      struct integrity_iint_cache *iint)
{
	if (!evm_key_loaded() || !evm_protected_xattr(xattr_name))
		return INTEGRITY_UNKNOWN;

	if (!iint) {
		iint = integrity_iint_find(d_backing_inode(dentry));
		if (!iint)
			return INTEGRITY_UNKNOWN;
	}
	return evm_verify_hmac(dentry, xattr_name, xattr_value,
				 xattr_value_len, iint);
}
EXPORT_SYMBOL_GPL(evm_verifyxattr);

/*
 * evm_verify_current_integrity - verify the dentry's metadata integrity
 * @dentry: pointer to the affected dentry
 *
 * Verify and return the dentry's metadata integrity. The exceptions are
 * before EVM is initialized or in 'fix' mode.
 */
static enum integrity_status evm_verify_current_integrity(struct dentry *dentry)
{
	struct inode *inode = d_backing_inode(dentry);

	if (!evm_key_loaded() || !S_ISREG(inode->i_mode) || evm_fixmode)
		return 0;
	return evm_verify_hmac(dentry, NULL, NULL, 0, NULL);
}

/*
 * evm_xattr_acl_change - check if passed ACL changes the inode mode
 * @dentry: pointer to the affected dentry
 * @xattr_name: requested xattr
 * @xattr_value: requested xattr value
 * @xattr_value_len: requested xattr value length
 *
 * Check if passed ACL changes the inode mode, which is protected by EVM.
 *
 * Returns 1 if passed ACL causes inode mode change, 0 otherwise.
 */
static int evm_xattr_acl_change(struct dentry *dentry, const char *xattr_name,
				const void *xattr_value, size_t xattr_value_len)
{
	umode_t mode;
	struct posix_acl *acl = NULL, *acl_res;
	struct inode *inode = d_backing_inode(dentry);
	int rc;

	/* UID/GID in ACL have been already converted from user to init ns */
	acl = posix_acl_from_xattr(&init_user_ns, xattr_value, xattr_value_len);
	if (!acl)
		return 1;

	acl_res = acl;
	rc = posix_acl_update_mode(inode, &mode, &acl_res);

	posix_acl_release(acl);

	if (rc)
		return 1;

	if (inode->i_mode != mode)
		return 1;

	return 0;
}

/*
 * evm_xattr_change - check if passed xattr value differs from current value
 * @dentry: pointer to the affected dentry
 * @xattr_name: requested xattr
 * @xattr_value: requested xattr value
 * @xattr_value_len: requested xattr value length
 *
 * Check if passed xattr value differs from current value.
 *
 * Returns 1 if passed xattr value differs from current value, 0 otherwise.
 */
static int evm_xattr_change(struct dentry *dentry, const char *xattr_name,
			    const void *xattr_value, size_t xattr_value_len)
{
	char *xattr_data = NULL;
	int rc = 0;

	if (posix_xattr_acl(xattr_name))
		return evm_xattr_acl_change(dentry, xattr_name, xattr_value,
					    xattr_value_len);

	rc = vfs_getxattr_alloc(dentry, xattr_name, &xattr_data, 0, GFP_NOFS);
	if (rc < 0)
		return 1;

	if (rc == xattr_value_len)
		rc = memcmp(xattr_value, xattr_data, rc);
	else
		rc = 1;

	kfree(xattr_data);
	return rc;
}

/*
 * evm_protect_xattr - protect the EVM extended attribute
 *
 * Prevent security.evm from being modified or removed without the
 * necessary permissions or when the existing value is invalid.
 *
 * The posix xattr acls are 'system' prefixed, which normally would not
 * affect security.evm.  An interesting side affect of writing posix xattr
 * acls is their modifying of the i_mode, which is included in security.evm.
 * For posix xattr acls only, permit security.evm, even if it currently
 * doesn't exist, to be updated unless the EVM signature is immutable.
 */
static int evm_protect_xattr(struct dentry *dentry, const char *xattr_name,
			     const void *xattr_value, size_t xattr_value_len)
{
	enum integrity_status evm_status;

	if (strcmp(xattr_name, XATTR_NAME_EVM) == 0) {
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
	} else if (!evm_protected_xattr(xattr_name)) {
		if (!posix_xattr_acl(xattr_name))
			return 0;
		evm_status = evm_verify_current_integrity(dentry);
		if ((evm_status == INTEGRITY_PASS) ||
		    (evm_status == INTEGRITY_NOXATTRS))
			return 0;
		goto out;
	}

	evm_status = evm_verify_current_integrity(dentry);
	if (evm_status == INTEGRITY_NOXATTRS) {
		struct integrity_iint_cache *iint;

		iint = integrity_iint_find(d_backing_inode(dentry));
		if (iint && (iint->flags & IMA_NEW_FILE))
			return 0;

		/* exception for pseudo filesystems */
		if (dentry->d_sb->s_magic == TMPFS_MAGIC
		    || dentry->d_sb->s_magic == SYSFS_MAGIC)
			return 0;

		integrity_audit_msg(AUDIT_INTEGRITY_METADATA,
				    dentry->d_inode, dentry->d_name.name,
				    "update_metadata",
				    integrity_status_msg[evm_status],
				    -EPERM, 0);
	}
out:
	if (evm_ignore_error_safe(evm_status))
		return 0;

	/*
	 * Writing other xattrs is safe for portable signatures, as portable
	 * signatures are immutable and can never be updated.
	 */
	if (evm_status == INTEGRITY_FAIL_IMMUTABLE)
		return 0;

	if (evm_status == INTEGRITY_PASS_IMMUTABLE &&
	    !evm_xattr_change(dentry, xattr_name, xattr_value, xattr_value_len))
		return 0;

	if (evm_status != INTEGRITY_PASS)
		integrity_audit_msg(AUDIT_INTEGRITY_METADATA, d_backing_inode(dentry),
				    dentry->d_name.name, "appraise_metadata",
				    integrity_status_msg[evm_status],
				    -EPERM, 0);
	return evm_status == INTEGRITY_PASS ? 0 : -EPERM;
}

/**
 * evm_inode_setxattr - protect the EVM extended attribute
 * @dentry: pointer to the affected dentry
 * @xattr_name: pointer to the affected extended attribute name
 * @xattr_value: pointer to the new extended attribute value
 * @xattr_value_len: pointer to the new extended attribute value length
 *
 * Before allowing the 'security.evm' protected xattr to be updated,
 * verify the existing value is valid.  As only the kernel should have
 * access to the EVM encrypted key needed to calculate the HMAC, prevent
 * userspace from writing HMAC value.  Writing 'security.evm' requires
 * requires CAP_SYS_ADMIN privileges.
 */
int evm_inode_setxattr(struct dentry *dentry, const char *xattr_name,
		       const void *xattr_value, size_t xattr_value_len)
{
	const struct evm_ima_xattr_data *xattr_data = xattr_value;

	/* Policy permits modification of the protected xattrs even though
	 * there's no HMAC key loaded
	 */
	if (evm_initialized & EVM_ALLOW_METADATA_WRITES)
		return 0;

	if (strcmp(xattr_name, XATTR_NAME_EVM) == 0) {
		if (!xattr_value_len)
			return -EINVAL;
		if (xattr_data->type != EVM_IMA_XATTR_DIGSIG &&
		    xattr_data->type != EVM_XATTR_PORTABLE_DIGSIG &&
		    xattr_data->type != EVM_IMA_XATTR_DIGEST_LIST)
			return -EPERM;
	}
	return evm_protect_xattr(dentry, xattr_name, xattr_value,
				 xattr_value_len);
}

/**
 * evm_inode_removexattr - protect the EVM extended attribute
 * @dentry: pointer to the affected dentry
 * @xattr_name: pointer to the affected extended attribute name
 *
 * Removing 'security.evm' requires CAP_SYS_ADMIN privileges and that
 * the current value is valid.
 */
int evm_inode_removexattr(struct dentry *dentry, const char *xattr_name)
{
	/* Policy permits modification of the protected xattrs even though
	 * there's no HMAC key loaded
	 */
	if (evm_initialized & EVM_ALLOW_METADATA_WRITES)
		return 0;

	return evm_protect_xattr(dentry, xattr_name, NULL, 0);
}

static void evm_reset_status(struct inode *inode)
{
	struct integrity_iint_cache *iint;

	iint = integrity_iint_find(inode);
	if (iint)
		iint->evm_status = INTEGRITY_UNKNOWN;
}

/**
 * evm_status_revalidate - report whether EVM status re-validation is necessary
 * @xattr_name: pointer to the affected extended attribute name
 *
 * Report whether callers of evm_verifyxattr() should re-validate the
 * EVM status.
 *
 * Return true if re-validation is necessary, false otherwise.
 */
bool evm_status_revalidate(const char *xattr_name)
{
	if (!evm_key_loaded())
		return false;

	/* evm_inode_post_setattr() passes NULL */
	if (!xattr_name)
		return true;

	if (!evm_protected_xattr(xattr_name) && !posix_xattr_acl(xattr_name) &&
	    strcmp(xattr_name, XATTR_NAME_EVM))
		return false;

	return true;
}

/**
 * evm_inode_post_setxattr - update 'security.evm' to reflect the changes
 * @dentry: pointer to the affected dentry
 * @xattr_name: pointer to the affected extended attribute name
 * @xattr_value: pointer to the new extended attribute value
 * @xattr_value_len: pointer to the new extended attribute value length
 *
 * Update the HMAC stored in 'security.evm' to reflect the change.
 *
 * No need to take the i_mutex lock here, as this function is called from
 * __vfs_setxattr_noperm().  The caller of which has taken the inode's
 * i_mutex lock.
 */
void evm_inode_post_setxattr(struct dentry *dentry, const char *xattr_name,
			     const void *xattr_value, size_t xattr_value_len)
{
	if (!evm_status_revalidate(xattr_name))
		return;

	evm_reset_status(dentry->d_inode);

	if (!strcmp(xattr_name, XATTR_NAME_EVM))
		return;

	evm_update_evmxattr(dentry, xattr_name, xattr_value, xattr_value_len);
}

/**
 * evm_inode_post_removexattr - update 'security.evm' after removing the xattr
 * @dentry: pointer to the affected dentry
 * @xattr_name: pointer to the affected extended attribute name
 *
 * Update the HMAC stored in 'security.evm' to reflect removal of the xattr.
 *
 * No need to take the i_mutex lock here, as this function is called from
 * vfs_removexattr() which takes the i_mutex.
 */
void evm_inode_post_removexattr(struct dentry *dentry, const char *xattr_name)
{
	if (!evm_status_revalidate(xattr_name))
		return;

	evm_reset_status(dentry->d_inode);

	if (!strcmp(xattr_name, XATTR_NAME_EVM))
		return;

	evm_update_evmxattr(dentry, xattr_name, NULL, 0);
}

static int evm_attr_change(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = d_backing_inode(dentry);
	unsigned int ia_valid = attr->ia_valid;

	if ((!(ia_valid & ATTR_UID) || uid_eq(attr->ia_uid, inode->i_uid)) &&
	    (!(ia_valid & ATTR_GID) || gid_eq(attr->ia_gid, inode->i_gid)) &&
	    (!(ia_valid & ATTR_MODE) || attr->ia_mode == inode->i_mode))
		return 0;

	return 1;
}

/**
 * evm_inode_setattr - prevent updating an invalid EVM extended attribute
 * @dentry: pointer to the affected dentry
 *
 * Permit update of file attributes when files have a valid EVM signature,
 * except in the case of them having an immutable portable signature.
 */
int evm_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
	unsigned int ia_valid = attr->ia_valid;
	enum integrity_status evm_status;

	/* Policy permits modification of the protected attrs even though
	 * there's no HMAC key loaded
	 */
	if (evm_initialized & EVM_ALLOW_METADATA_WRITES)
		return 0;

	if (!(ia_valid & (ATTR_MODE | ATTR_UID | ATTR_GID)))
		return 0;
	evm_status = evm_verify_current_integrity(dentry);
	/*
	 * Writing attrs is safe for portable signatures, as portable signatures
	 * are immutable and can never be updated.
	 */
	if ((evm_status == INTEGRITY_PASS) ||
	    (evm_status == INTEGRITY_NOXATTRS) ||
	    (evm_status == INTEGRITY_FAIL_IMMUTABLE) ||
	    (evm_ignore_error_safe(evm_status)))
		return 0;

	if (evm_status == INTEGRITY_PASS_IMMUTABLE &&
	    !evm_attr_change(dentry, attr))
		return 0;

	integrity_audit_msg(AUDIT_INTEGRITY_METADATA, d_backing_inode(dentry),
			    dentry->d_name.name, "appraise_metadata",
			    integrity_status_msg[evm_status], -EPERM, 0);
	return -EPERM;
}

/**
 * evm_inode_post_setattr - update 'security.evm' after modifying metadata
 * @dentry: pointer to the affected dentry
 * @ia_valid: for the UID and GID status
 *
 * For now, update the HMAC stored in 'security.evm' to reflect UID/GID
 * changes.
 *
 * This function is called from notify_change(), which expects the caller
 * to lock the inode's i_mutex.
 */
void evm_inode_post_setattr(struct dentry *dentry, int ia_valid)
{
	if (!evm_status_revalidate(NULL))
		return;

	evm_reset_status(dentry->d_inode);

	if (ia_valid & (ATTR_MODE | ATTR_UID | ATTR_GID))
		evm_update_evmxattr(dentry, NULL, NULL, 0);
}

/*
 * evm_inode_init_security - initializes security.evm HMAC value
 */
int evm_inode_init_security(struct inode *inode,
				 const struct xattr *lsm_xattr,
				 struct xattr *evm_xattr)
{
	struct evm_xattr *xattr_data;
	int rc;

	if (!(evm_initialized & EVM_INIT_HMAC) ||
	    !evm_protected_xattr(lsm_xattr->name))
		return 0;

	xattr_data = kzalloc(sizeof(*xattr_data), GFP_NOFS);
	if (!xattr_data)
		return -ENOMEM;

	xattr_data->data.type = EVM_XATTR_HMAC;
	rc = evm_init_hmac(inode, lsm_xattr, xattr_data->digest);
	if (rc < 0)
		goto out;

	evm_xattr->value = xattr_data;
	evm_xattr->value_len = hash_digest_size[evm_hash_algo] + 1;
	evm_xattr->name = XATTR_EVM_SUFFIX;
	return 0;
out:
	kfree(xattr_data);
	return rc;
}
EXPORT_SYMBOL_GPL(evm_inode_init_security);

#ifdef CONFIG_EVM_LOAD_X509
void __init evm_load_x509(void)
{
	int rc;

	rc = integrity_load_x509(INTEGRITY_KEYRING_EVM, CONFIG_EVM_X509_PATH);
	if (!rc)
		evm_initialized |= EVM_INIT_X509;
}
#endif

static int __init init_evm(void)
{
	int error, i;
	struct list_head *pos, *q;

	i = match_string(hash_algo_name, HASH_ALGO__LAST,
			 CONFIG_EVM_DEFAULT_HASH);
	if (i >= 0)
		evm_hash_algo = i;

	evm_init_config();

	error = integrity_init_keyring(INTEGRITY_KEYRING_EVM);
	if (error)
		goto error;

	error = evm_init_secfs();
	if (error < 0) {
		pr_info("Error registering secfs\n");
		goto error;
	}

error:
	if (error != 0) {
		if (!list_empty(&evm_config_xattrnames)) {
			list_for_each_safe(pos, q, &evm_config_xattrnames)
				list_del(pos);
		}
	}

	return error;
}

late_initcall(init_evm);
