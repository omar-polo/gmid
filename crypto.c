/*
 * Copyright (c) 2023 Omar Polo <op@omarpolo.com>
 * Copyright (c) 2014 Reyk Floeter <reyk@openbsd.org>
 * Copyright (c) 2012 Gilles Chehade <gilles@poolp.org>
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

#include <string.h>

#include <openssl/err.h>
#include <openssl/pem.h>

#include "log.h"
#include "proc.h"

#ifndef nitems
#define nitems(_a) (sizeof((_a)) / sizeof((_a)[0]))
#endif

static void crypto_init(struct privsep *, struct privsep_proc *, void *);
static int crypto_dispatch_parent(int, struct privsep_proc *, struct imsg *);
static int crypto_dispatch_server(int, struct privsep_proc *, struct imsg *);

static struct privsep_proc procs[] = {
	{ "parent",	PROC_PARENT,	crypto_dispatch_parent },
	{ "server",	PROC_SERVER,	crypto_dispatch_server },
};

struct imsg_crypto_req {
	uint64_t	 id;
	char		 hash[TLS_CERT_HASH_SIZE];
	size_t		 flen;
	size_t		 tlen;
	int		 padding;
	/* followed by flen bytes of `from'. */
};

struct imsg_crypto_res {
	uint64_t	 id;
	int		 ret;
	size_t		 len;
	/* followed by len bytes of reply */
};

static uint64_t		 reqid;
static struct conf	*conf;

void
crypto(struct privsep *ps, struct privsep_proc *p)
{
	proc_run(ps, p, procs, nitems(procs), crypto_init, NULL);
}

static void
crypto_init(struct privsep *ps, struct privsep_proc *p, void *arg)
{
#if 0
	static volatile int attached;
	while (!attached) sleep(1);
#endif

	conf = ps->ps_env;

	sandbox_crypto_process();
}

static int
crypto_dispatch_parent(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	switch (imsg->hdr.type) {
	case IMSG_RECONF_START:
	case IMSG_RECONF_CERT:
	case IMSG_RECONF_KEY:
	case IMSG_RECONF_END:
		if (config_recv(conf, imsg) == -1)
			return -1;
		break;
	default:
		return -1;
	}

	return 0;
}

static EVP_PKEY *
get_pkey(const char *hash)
{
	struct pki *pki;

	TAILQ_FOREACH(pki, &conf->pkis, pkis) {
		if (!strcmp(pki->hash, hash))
			return pki->pkey;
	}

	return NULL;
}

static int
crypto_dispatch_server(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	struct privsep		*ps = p->p_ps;
	RSA			*rsa = NULL;
	EC_KEY			*ecdsa = NULL;
	EVP_PKEY		*pkey;
	struct imsg_crypto_req	 req;
	struct imsg_crypto_res	 res;
	struct iovec		 iov[2];
	const void		*from;
	unsigned char		*data, *to;
	size_t			 datalen;
	int			 n, ret;
	unsigned int		 len;

	data = imsg->data;
	datalen = IMSG_DATA_SIZE(imsg);

	switch (imsg->hdr.type) {
	case IMSG_CRYPTO_RSA_PRIVENC:
	case IMSG_CRYPTO_RSA_PRIVDEC:
		if (datalen < sizeof(req))
			fatalx("size mismatch for imsg %d", imsg->hdr.type);
		memcpy(&req, data, sizeof(req));
		if (datalen != sizeof(req) + req.flen)
			fatalx("size mismatch for imsg %d", imsg->hdr.type);
		from = data + sizeof(req);

		if ((pkey = get_pkey(req.hash)) == NULL ||
		    (rsa = EVP_PKEY_get1_RSA(pkey)) == NULL)
			fatalx("invalid pkey hash");

		if ((to = calloc(1, req.tlen)) == NULL)
			fatal("calloc");

		if (imsg->hdr.type == IMSG_CRYPTO_RSA_PRIVENC)
			ret = RSA_private_encrypt(req.flen, from,
			    to, rsa, req.padding);
		else
			ret = RSA_private_decrypt(req.flen, from,
			    to, rsa, req.padding);

		memset(&res, 0, sizeof(res));
		res.id = req.id;
		res.ret = ret;

		memset(&iov, 0, sizeof(iov));
		n = 0;
		iov[n].iov_base = &res;
		iov[n].iov_len = sizeof(res);
		n++;

		if (ret > 0) {
			res.len = ret;
			iov[n].iov_base = to;
			iov[n].iov_len = ret;
			n++;
		}

		log_debug("replying to server #%d", imsg->hdr.pid);
		if (proc_composev_imsg(ps, PROC_SERVER, imsg->hdr.pid - 1,
		    imsg->hdr.type, 0, -1, iov, n) == -1)
			fatal("proc_composev_imsg");

		if (proc_flush_imsg(ps, PROC_SERVER, imsg->hdr.pid - 1) == -1)
			fatal("proc_flush_imsg");

		free(to);
		RSA_free(rsa);
		break;

	case IMSG_CRYPTO_ECDSA_SIGN:
		if (datalen < sizeof(req))
			fatalx("size mismatch for imsg %d", imsg->hdr.type);
		memcpy(&req, data, sizeof(req));
		if (datalen != sizeof(req) + req.flen)
			fatalx("size mismatch for imsg %d", imsg->hdr.type);
		from = data + sizeof(req);

		if ((pkey = get_pkey(req.hash)) == NULL ||
		    (ecdsa = EVP_PKEY_get1_EC_KEY(pkey)) == NULL)
			fatalx("invalid pkey hash");

		len = ECDSA_size(ecdsa);
		if ((to = calloc(1, len)) == NULL)
			fatal("calloc");
		ret = ECDSA_sign(0, from, req.flen, to, &len, ecdsa);

		memset(&res, 0, sizeof(res));
		res.id = req.id;
		res.ret = ret;

		memset(&iov, 0, sizeof(iov));
		n = 0;
		iov[0].iov_base = &res;
		iov[0].iov_len = sizeof(res);
		n++;

		if (ret > 0) {
			res.len = len;
			iov[n].iov_base = to;
			iov[n].iov_len = len;
			n++;
		}

		log_debug("replying to server #%d", imsg->hdr.pid);
		if (proc_composev_imsg(ps, PROC_SERVER, imsg->hdr.pid - 1,
		    imsg->hdr.type, 0, -1, iov, n) == -1)
			fatal("proc_composev_imsg");

		if (proc_flush_imsg(ps, PROC_SERVER, imsg->hdr.pid - 1) == -1)
			fatal("proc_flush_imsg");

		free(to);
		EC_KEY_free(ecdsa);
		break;

	default:
		return -1;
	}

	return 0;
}


/*
 * RSA privsep engine (called from unprivileged processes)
 */

static const RSA_METHOD	*rsa_default;
static RSA_METHOD	*rsae_method;

static int
rsae_send_imsg(int flen, const unsigned char *from, unsigned char *to,
    RSA *rsa, int padding, unsigned int cmd)
{
	struct imsg_crypto_req	 req;
	struct iovec		 iov[2];
	struct imsg_crypto_res	 res;
	struct imsgev		*iev;
	struct privsep_proc	*p;
	struct privsep		*ps = conf->ps;
	struct imsgbuf		*ibuf;
	struct imsg		 imsg;
	int			 ret = 0;
	int			 n, done = 0;
	const void		*toptr;
	char			*hash;
	unsigned char		*data;
	size_t			 datalen;

	if ((hash = RSA_get_ex_data(rsa, 0)) == NULL)
		return (0);

	/*
	 * Send a synchronous imsg because we cannot defer the RSA
	 * operation in OpenSSL's engine layer.
	 */
	memset(&req, 0, sizeof(req));
	req.id = ++reqid;
	if (strlcpy(req.hash, hash, sizeof(req.hash)) >= sizeof(req.hash))
		fatalx("%s: hash too long (%zu)", __func__, strlen(hash));
	req.flen = flen;
	req.tlen = RSA_size(rsa);
	req.padding = padding;

	memset(&iov, 0, sizeof(iov));
	iov[0].iov_base = &req;
	iov[0].iov_len = sizeof(req);
	iov[1].iov_base = (void *)from;
	iov[1].iov_len = flen;

	if (proc_composev(ps, PROC_CRYPTO, cmd, iov, 2) == -1)
		fatal("proc_composev");

	if (proc_flush_imsg(ps, PROC_CRYPTO, -1) == -1)
		fatal("proc_flush_imsg");

	iev = ps->ps_ievs[PROC_CRYPTO];
	p = iev->proc;
	ibuf = &iev->ibuf;

	while (!done) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			fatalx("imsg_read");
		if (n == 0)
			fatalx("pipe closed");

		while (!done) {
			if ((n = imsg_get(ibuf, &imsg)) == -1)
				fatalx("imsg_get error");
			if (n == 0)
				break;

#if DEBUG > 1
			log_debug(
			    "%s: %s %d got imsg %d peerid %d from %s %d",
			    __func__, title, 1, imsg.hdr.type,
			    imsg.hdr.peerid, "crypto", imsg.hdr.pid);
#endif

			if ((p->p_cb)(ibuf->fd, p, &imsg) == 0) {
				/* Message was handled by the callback */
				imsg_free(&imsg);
				continue;
			}

			switch (imsg.hdr.type) {
			case IMSG_CRYPTO_RSA_PRIVENC:
			case IMSG_CRYPTO_RSA_PRIVDEC:
				break;
			default:
				fatalx("%s: %s %d got invalid imsg %d"
				    " peerid %d from %s %d",
				    __func__, "server", ps->ps_instance + 1,
				    imsg.hdr.type, imsg.hdr.peerid,
				    "crypto", imsg.hdr.pid);
			}

			data = imsg.data;
			datalen = IMSG_DATA_SIZE(&imsg);
			if (datalen < sizeof(res))
				fatalx("size mismatch for imsg %d",
				    imsg.hdr.type);
			memcpy(&res, data, sizeof(res));
			if (datalen != sizeof(res) + res.ret)
				fatalx("size mismatch for imsg %d",
				    imsg.hdr.type);
			ret = res.ret;
			toptr = data + sizeof(res);

			if (res.id != reqid)
				fatalx("invalid id; got %llu, want %llu",
				    (unsigned long long)res.id,
				    (unsigned long long)reqid);
			if (res.ret > 0)
				memcpy(to, toptr, res.len);

			done = 1;

			imsg_free(&imsg);
		}
	}
	imsg_event_add(iev);

	return (ret);
}

static int
rsae_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa,
    int padding)
{
	log_debug("debug: %s", __func__);
	if (RSA_get_ex_data(rsa, 0) != NULL)
		return (rsae_send_imsg(flen, from, to, rsa, padding,
		    IMSG_CRYPTO_RSA_PRIVENC));
	return (RSA_meth_get_priv_enc(rsa_default)(flen, from, to, rsa, padding));
}

static int
rsae_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa,
    int padding)
{
	log_debug("debug: %s", __func__);
	if (RSA_get_ex_data(rsa, 0) != NULL)
		return (rsae_send_imsg(flen, from, to, rsa, padding,
		    IMSG_CRYPTO_RSA_PRIVDEC));

	return (RSA_meth_get_priv_dec(rsa_default)(flen, from, to, rsa, padding));
}


/*
 * ECDSA privsep engine (called from unprivileged processes)
 */

static const EC_KEY_METHOD	*ecdsa_default;
static EC_KEY_METHOD		*ecdsae_method;

static ECDSA_SIG *
ecdsae_send_enc_imsg(const unsigned char *dgst, int dgst_len,
    const BIGNUM *inv, const BIGNUM *rp, EC_KEY *eckey)
{
	ECDSA_SIG		*sig = NULL;
	struct imsg_crypto_req	 req;
	struct iovec		 iov[2];
	struct imsg_crypto_res	 res;
	struct imsgev		*iev;
	struct privsep_proc	*p;
	struct privsep		*ps = conf->ps;
	struct imsgbuf		*ibuf;
	struct imsg		 imsg;
	int			 n, done = 0;
	const void		*toptr;
	char			*hash;
	unsigned char		*data;
	size_t			 datalen;

	if ((hash = EC_KEY_get_ex_data(eckey, 0)) == NULL)
		return (0);

	/*
	 * Send a synchronous imsg because we cannot defer the RSA
	 * operation in OpenSSL's engine layer.
	 */
	memset(&req, 0, sizeof(req));
	req.id = ++reqid;
	if (strlcpy(req.hash, hash, sizeof(req.hash)) >= sizeof(req.hash))
		fatalx("%s: hash too long (%zu)", __func__, strlen(hash));
	req.flen = dgst_len;

	memset(&iov, 0, sizeof(iov));
	iov[0].iov_base = &req;
	iov[0].iov_len = sizeof(req);
	iov[1].iov_base = (void *)dgst;
	iov[1].iov_len = dgst_len;

	if (proc_composev(ps, PROC_CRYPTO, IMSG_CRYPTO_ECDSA_SIGN, iov, 2) == -1)
		fatal("proc_composev");

	if (proc_flush_imsg(ps, PROC_CRYPTO, -1) == -1)
		fatal("proc_flush_imsg");

	iev = ps->ps_ievs[PROC_CRYPTO];
	p = iev->proc;
	ibuf = &iev->ibuf;

	while (!done) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			fatalx("imsg_read");
		if (n == 0)
			fatalx("pipe closed");

		while (!done) {
			if ((n = imsg_get(ibuf, &imsg)) == -1)
				fatalx("imsg_get error");
			if (n == 0)
				break;

#if DEBUG > 1
			log_debug(
			    "%s: %s %d got imsg %d peerid %d from %s %d",
			    __func__, title, 1, imsg.hdr.type,
			    imsg.hdr.peerid, "crypto", imsg.hdr.pid);
#endif

			if (imsg.hdr.type != IMSG_CRYPTO_ECDSA_SIGN &&
			    crypto_dispatch_server(ibuf->fd, p, &imsg) == 0) {
				/* Message was handled by the callback */
				imsg_free(&imsg);
				continue;
			}

			if (imsg.hdr.type != IMSG_CRYPTO_ECDSA_SIGN)
				fatalx("%s: %s %d got invalid imsg %d"
				    " peerid %d from %s %d",
				    __func__, "server", ps->ps_instance + 1,
				    imsg.hdr.type, imsg.hdr.peerid,
				    "crypto", imsg.hdr.pid);

			data = imsg.data;
			datalen = IMSG_DATA_SIZE(&imsg);
			if (datalen < sizeof(res))
				fatalx("size mismatch for imsg %d",
				    imsg.hdr.type);
			memcpy(&res, data, sizeof(res));
			if (datalen != sizeof(res) + res.len)
				fatalx("size mismatch for imsg %d",
				    imsg.hdr.type);
			toptr = data + sizeof(res);

			if (res.id != reqid)
				fatalx("invalid response id");
			if (res.ret > 0) {
				d2i_ECDSA_SIG(&sig,
				    (const unsigned char **)&toptr, res.len);
			}

			done = 1;

			imsg_free(&imsg);
		}
	}
	imsg_event_add(iev);

	return (sig);
}

static ECDSA_SIG *
ecdsae_do_sign(const unsigned char *dgst, int dgst_len, const BIGNUM *inv,
    const BIGNUM *rp, EC_KEY *eckey)
{
	ECDSA_SIG *(*psign_sig)(const unsigned char *, int, const BIGNUM *,
	    const BIGNUM *, EC_KEY *);

	log_debug("debug: %s", __func__);
	if (EC_KEY_get_ex_data(eckey, 0) != NULL)
		return (ecdsae_send_enc_imsg(dgst, dgst_len, inv, rp, eckey));
	EC_KEY_METHOD_get_sign(ecdsa_default, NULL, NULL, &psign_sig);
	return (psign_sig(dgst, dgst_len, inv, rp, eckey));
}


/*
 * Initialize the two engines.
 */

static void
rsa_engine_init(void)
{
	const char	*errstr;

	if ((rsa_default = RSA_get_default_method()) == NULL) {
		errstr = "RSA_get_default_method";
		goto fail;
	}

	if ((rsae_method = RSA_meth_dup(rsa_default)) == NULL) {
		errstr = "RSA_meth_dup";
		goto fail;
	}

	RSA_meth_set_priv_enc(rsae_method, rsae_priv_enc);
	RSA_meth_set_priv_dec(rsae_method, rsae_priv_dec);

	RSA_meth_set_flags(rsae_method,
	    RSA_meth_get_flags(rsa_default) | RSA_METHOD_FLAG_NO_CHECK);
	RSA_meth_set0_app_data(rsae_method,
	    RSA_meth_get0_app_data(rsa_default));

	RSA_set_default_method(rsae_method);

	return;

 fail:
	ssl_error(errstr);
	fatalx("%s", errstr);
}

static void
ecdsa_engine_init(void)
{
	int (*sign)(int, const unsigned char *, int, unsigned char *,
	    unsigned int *, const BIGNUM *, const BIGNUM *, EC_KEY *);
	int (*sign_setup)(EC_KEY *, BN_CTX *, BIGNUM **, BIGNUM **);
	const char *errstr;

	if ((ecdsa_default = EC_KEY_get_default_method()) == NULL) {
		errstr = "EC_KEY_get_default_method";
		goto fail;
	}

	if ((ecdsae_method = EC_KEY_METHOD_new(ecdsa_default)) == NULL) {
		errstr = "EC_KEY_METHOD_new";
		goto fail;
	}

	EC_KEY_METHOD_get_sign(ecdsa_default, &sign, &sign_setup, NULL);
	EC_KEY_METHOD_set_sign(ecdsae_method, sign, sign_setup,
	    ecdsae_do_sign);

	EC_KEY_set_default_method(ecdsae_method);

	return;

 fail:
	ssl_error(errstr);
	fatalx("%s", errstr);
}

void
crypto_engine_init(struct conf *c)
{
	conf = c;

	rsa_engine_init();
	ecdsa_engine_init();
}

