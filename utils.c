/*
 * Copyright (c) 2021 Omar Polo <op@omarpolo.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "gmid.h"

#include <errno.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

static sigset_t set;

void
block_signals(void)
{
	sigset_t new;

	sigemptyset(&new);
	sigaddset(&new, SIGHUP);
	sigprocmask(SIG_BLOCK, &new, &set);
}

void
unblock_signals(void)
{
	sigprocmask(SIG_SETMASK, &set, NULL);
}

int
starts_with(const char *str, const char *prefix)
{
	size_t i;

	if (prefix == NULL)
		return 0;

	for (i = 0; prefix[i] != '\0'; ++i)
		if (str[i] != prefix[i])
			return 0;
	return 1;
}

int
ends_with(const char *str, const char *sufx)
{
	size_t i, j;

	i = strlen(str);
	j = strlen(sufx);

	if (j > i)
		return 0;

	i -= j;
	for (j = 0; str[i] != '\0'; i++, j++)
		if (str[i] != sufx[j])
			return 0;
	return 1;
}

ssize_t
filesize(int fd)
{
	ssize_t len;

	if ((len = lseek(fd, 0, SEEK_END)) == -1)
		return -1;
	if (lseek(fd, 0, SEEK_SET) == -1)
		return -1;
	return len;
}

char *
absolutify_path(const char *path)
{
	char *wd, *r;

	if (*path == '/') {
		if ((r = strdup(path)) == NULL)
			err(1, "strdup");
		return r;
	}

	wd = getcwd(NULL, 0);
	if (asprintf(&r, "%s/%s", wd, path) == -1)
		err(1, "asprintf");
	free(wd);
	return r;
}

char *
xstrdup(const char *s)
{
	char *d;

	if ((d = strdup(s)) == NULL)
		err(1, "strdup");
	return d;
}

void
gen_certificate(const char *hostname, const char *certpath, const char *keypath)
{
	BIGNUM		*e;
	EVP_PKEY	*pkey;
	RSA		*rsa;
	X509		*x509;
	X509_NAME	*name;
	FILE		*f;
	const unsigned char *org = (const unsigned char*)"gmid";
	const unsigned char *host = (const unsigned char*)hostname;

	log_notice(NULL,
	    "generating new certificate for %s (it could take a while)",
	    host);

	if ((pkey = EVP_PKEY_new()) == NULL)
                fatal("couldn't create a new private key");

	if ((rsa = RSA_new()) == NULL)
		fatal("couldn't generate rsa");

	if ((e = BN_new()) == NULL)
		fatal("couldn't allocate a bignum");

	BN_set_word(e, 17);
	if (!RSA_generate_key_ex(rsa, 4096, e, NULL))
		fatal("couldn't generate a rsa key");

	if (!EVP_PKEY_assign_RSA(pkey, rsa))
		fatal("couldn't assign the key");

	if ((x509 = X509_new()) == NULL)
		fatal("couldn't generate the X509 certificate");

	ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), 315360000L); /* 10 years */

	if (!X509_set_pubkey(x509, pkey))
		fatal("couldn't set the public key");

	name = X509_get_subject_name(x509);
	if (!X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, org, -1, -1, 0))
		fatal("couldn't add N to cert");
	if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, host, -1, -1, 0))
		fatal("couldn't add CN to cert");
	X509_set_issuer_name(x509, name);

	if (!X509_sign(x509, pkey, EVP_sha256()))
                fatal("couldn't sign the certificate");

	if ((f = fopen(keypath, "w")) == NULL)
		fatal("fopen(%s): %s", keypath, strerror(errno));
	if (!PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL))
		fatal("couldn't write private key");
	fclose(f);

	if ((f = fopen(certpath, "w")) == NULL)
		fatal("fopen(%s): %s", certpath, strerror(errno));
	if (!PEM_write_X509(f, x509))
		fatal("couldn't write cert");
	fclose(f);

	BN_free(e);
	X509_free(x509);
	RSA_free(rsa);
}

X509_STORE *
load_ca(const char *path)
{
	FILE		*f = NULL;
	X509		*x = NULL;
	X509_STORE	*store;

	if ((store = X509_STORE_new()) == NULL)
		return NULL;

	if ((f = fopen(path, "r")) == NULL)
		goto err;

	if ((x = PEM_read_X509(f, NULL, NULL, NULL)) == NULL)
		goto err;

	if (X509_check_ca(x) == 0)
		goto err;

	if (!X509_STORE_add_cert(store, x))
		goto err;

	X509_free(x);
	fclose(f);
	return store;

err:
	X509_STORE_free(store);
	if (x != NULL)
		X509_free(x);
	if (f != NULL)
		fclose(f);
	return NULL;
}

int
validate_against_ca(X509_STORE *ca, const uint8_t *chain, size_t len)
{
	X509		*client;
	BIO		*m;
	X509_STORE_CTX	*ctx = NULL;
	int		 ret = 0;

	if ((m = BIO_new_mem_buf(chain, len)) == NULL)
		return 0;

	if ((client = PEM_read_bio_X509(m, NULL, NULL, NULL)) == NULL)
		goto end;

	if ((ctx = X509_STORE_CTX_new()) == NULL)
		goto end;

	if (!X509_STORE_CTX_init(ctx, ca, client, NULL))
		goto end;

	ret = X509_verify_cert(ctx);

end:
	BIO_free(m);
	if (client != NULL)
		X509_free(client);
	if (ctx != NULL)
		X509_STORE_CTX_free(ctx);
	return ret;
}
