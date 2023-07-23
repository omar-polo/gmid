/*
 * Copyright (c) 2021, 2023 Omar Polo <op@omarpolo.com>
 * Copyright (c) 2008 Pierre-Yves Ritschard <pyr@openbsd.org>
 * Copyright (c) 2008 Reyk Floeter <reyk@openbsd.org>
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
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include "log.h"

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
			fatal("strdup");
		return r;
	}

	wd = getcwd(NULL, 0);
	if (asprintf(&r, "%s/%s", wd, path) == -1)
		fatal("asprintf");
	free(wd);
	return r;
}

char *
xstrdup(const char *s)
{
	char *d;

	if ((d = strdup(s)) == NULL)
		fatal("strdup");
	return d;
}

void *
xcalloc(size_t nmemb, size_t size)
{
	void *d;

	if ((d = calloc(nmemb, size)) == NULL)
		fatal("calloc");
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
	const unsigned char *host = (const unsigned char*)hostname;

	log_info("generating new certificate for %s (it could take a while)",
	    host);

	if ((pkey = EVP_PKEY_new()) == NULL)
		fatalx("couldn't create a new private key");

	if ((rsa = RSA_new()) == NULL)
		fatalx("couldn't generate rsa");

	if ((e = BN_new()) == NULL)
		fatalx("couldn't allocate a bignum");

	BN_set_word(e, RSA_F4);
	if (!RSA_generate_key_ex(rsa, 4096, e, NULL))
		fatalx("couldn't generate a rsa key");

	if (!EVP_PKEY_assign_RSA(pkey, rsa))
		fatalx("couldn't assign the key");

	if ((x509 = X509_new()) == NULL)
		fatalx("couldn't generate the X509 certificate");

	ASN1_INTEGER_set(X509_get_serialNumber(x509), 0);
	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), 315360000L); /* 10 years */
	X509_set_version(x509, 3);

	if (!X509_set_pubkey(x509, pkey))
		fatalx("couldn't set the public key");

	name = X509_get_subject_name(x509);
	if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, host, -1, -1, 0))
		fatalx("couldn't add CN to cert");
	X509_set_issuer_name(x509, name);

	if (!X509_sign(x509, pkey, EVP_sha256()))
		fatalx("couldn't sign the certificate");

	if ((f = fopen(keypath, "w")) == NULL)
		fatal("can't open %s", keypath);
	if (!PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL))
		fatalx("couldn't write private key");
	fclose(f);

	if ((f = fopen(certpath, "w")) == NULL)
		fatal("can't open %s", certpath);
	if (!PEM_write_X509(f, x509))
		fatalx("couldn't write cert");
	fclose(f);

	BN_free(e);
	X509_free(x509);
	RSA_free(rsa);

	log_info("certificate successfully generated");
}

X509_STORE *
load_ca(uint8_t *d, size_t len)
{
	BIO		*in;
	X509		*x = NULL;
	X509_STORE	*store;

	if ((store = X509_STORE_new()) == NULL) {
		log_warnx("%s: X509_STORE_new failed", __func__);
		return NULL;
	}

	if ((in = BIO_new_mem_buf(d, len)) == NULL) {
		log_warnx("%s: BIO_new_mem_buf failed", __func__);
		goto err;
	}

	if ((x = PEM_read_bio_X509(in, NULL, NULL, NULL)) == NULL) {
		log_warnx("%s: PEM_read_bio_X509 failed", __func__);
		ssl_error("PEM_read_bio_X509");
		goto err;
	}

	if (X509_check_ca(x) == 0) {
		ssl_error("X509_check_ca");
		goto err;
	}

	if (!X509_STORE_add_cert(store, x)) {
		ssl_error("X509_STORE_add_cert");
		goto err;
	}

	X509_free(x);
	BIO_free(in);
	return store;

err:
	X509_STORE_free(store);
	if (x != NULL)
		X509_free(x);
	if (in != NULL)
		BIO_free(in);
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

void
ssl_error(const char *where)
{
	unsigned long	 code;
	char		 errbuf[128];

	while ((code = ERR_get_error()) != 0) {
		ERR_error_string_n(code, errbuf, sizeof(errbuf));
		log_debug("debug: SSL library error: %s: %s", where, errbuf);
	}
}

char *
ssl_pubkey_hash(const uint8_t *buf, size_t len)
{
	static const char hex[] = "0123456789abcdef";
	BIO		*in;
	X509		*x509 = NULL;
	char		*hash = NULL;
	size_t		 off;
	unsigned char	 digest[EVP_MAX_MD_SIZE];
	unsigned int	 dlen, i;

	if ((in = BIO_new_mem_buf(buf, len)) == NULL) {
		log_warnx("%s: BIO_new_mem_buf failed", __func__);
		return NULL;
	}

	if ((x509 = PEM_read_bio_X509(in, NULL, NULL, NULL)) == NULL) {
		log_warnx("%s: PEM_read_bio_X509 failed", __func__);
		ssl_error("PEM_read_bio_X509");
		goto fail;
	}

	if ((hash = malloc(TLS_CERT_HASH_SIZE)) == NULL) {
		log_warn("%s: malloc", __func__);
		goto fail;
	}

	if (X509_pubkey_digest(x509, EVP_sha256(), digest, &dlen) != 1) {
		log_warnx("%s: X509_pubkey_digest failed", __func__);
		ssl_error("X509_pubkey_digest");
		free(hash);
		hash = NULL;
		goto fail;
	}

	if (TLS_CERT_HASH_SIZE < 2 * dlen + sizeof("SHA256:"))
		fatalx("%s: hash buffer too small", __func__);

	off = strlcpy(hash, "SHA256:", TLS_CERT_HASH_SIZE);
	for (i = 0; i < dlen; ++i) {
		hash[off++] = hex[(digest[i] >> 4) & 0xf];
		hash[off++] = hex[digest[i] & 0xf];
	}
	hash[off] = '\0';

 fail:
	BIO_free(in);
	if (x509)
		X509_free(x509);
	return hash;
}

EVP_PKEY *
ssl_load_pkey(const uint8_t *buf, size_t len)
{
	BIO		*in;
	EVP_PKEY	*pkey;

	if ((in = BIO_new_mem_buf(buf, len)) == NULL) {
		log_warnx("%s: BIO_new_mem_buf failed", __func__);
		return NULL;
	}

	if ((pkey = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL)) == NULL) {
		log_warnx("%s: PEM_read_bio_PrivateKey failed", __func__);
		ssl_error("PEM_read_bio_PrivateKey");
	}

	BIO_free(in);
	return pkey;
}

struct vhost *
new_vhost(void)
{
	struct vhost *h;

	h = xcalloc(1, sizeof(*h));
	TAILQ_INIT(&h->addrs);
	TAILQ_INIT(&h->locations);
	TAILQ_INIT(&h->aliases);
	TAILQ_INIT(&h->proxies);
	return h;
}

struct location *
new_location(void)
{
	struct location *l;

	l = xcalloc(1, sizeof(*l));
	l->dirfd = -1;
	l->fcgi = -1;
	TAILQ_INIT(&l->params);
	return l;
}

struct proxy *
new_proxy(void)
{
	struct proxy *p;

	p = xcalloc(1, sizeof(*p));
	p->protocols = TLS_PROTOCOLS_DEFAULT;
	return p;
}
