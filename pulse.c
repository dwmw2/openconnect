/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2015 Intel Corporation.
 *
 * Author: David Woodhouse <dwmw2@infradead.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

/*
 * Grateful thanks to Tiebing Zhang, who did much of the hard work
 * of analysing and decoding the protocol.
 */

#include <config.h>

#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdarg.h>
#include <sys/types.h>

#define VENDOR_TCG 0x5597

#define IFT_VERSION_REQUEST 1
#define IFT_VERSION_RESPONSE 2
#define IFT_SASL_MECHANISMS 3
#define IFT_SASL_MECH_SELECT 4
#define IFT_SASL_DATA 5
#define IFT_SASL_RESULT 6

#define VENDOR_JUNIPER 0xa4c
#define VENDOR_JUNIPER2 0x583

#define AVP_VENDOR 0x80
#define AVP_MANDATORY 0x40

#define EAP_REQUEST 1
#define EAP_RESPONSE 2
#define EAP_SUCCESS 3
#define EAP_FAILURE 4

#define EAP_TYPE_IDENTITY 1
#define EAP_TYPE_TTLS 0x15
#define EAP_TYPE_EXPANDED 0xfe

#define EXPANDED_JUNIPER ((EAP_TYPE_EXPANDED << 24) | VENDOR_JUNIPER)

/* First word of all IF-T SASL packets */
#define JUNIPER_1 ((VENDOR_JUNIPER << 8) | 1)

#include "openconnect-internal.h"
int pulse_obtain_cookie(struct openconnect_info *vpninfo)
{
	return -EINVAL;
}

static void buf_append_be16(struct oc_text_buf *buf, uint16_t val)
{
	unsigned char b[2];

	store_be16(b, val);

	buf_append_bytes(buf, b, 2);
}

static void buf_append_be32(struct oc_text_buf *buf, uint32_t val)
{
	unsigned char b[4];

	store_be32(b, val);

	buf_append_bytes(buf, b, 4);
}

static void buf_append_ift_hdr(struct oc_text_buf *buf, uint32_t vendor, uint32_t type)
{
	uint32_t b[4];

	b[2] = 0;
	b[3] = 0;
	store_be32(&b[0], vendor);
	store_be32(&b[1], type);
	buf_append_bytes(buf, b, 16);
}

/* Append EAP header, using VENDOR_JUNIPER and the given subtype if
 * the main type is EAP_TYPE_EXPANDED */
static void buf_append_eap_hdr(struct oc_text_buf *buf, uint8_t code, uint8_t ident, uint8_t type,
			       uint32_t subtype)
{
	unsigned char b[24];

	/* All IF-T SASL frames start with this */
	buf_append_be32(buf, JUNIPER_1);

	b[0] = code;
	b[1] = ident;
	b[2] = b[3] = 0; /* Length is filled in later. */
	if (type == EAP_TYPE_EXPANDED) {
		store_be32(b + 4, EXPANDED_JUNIPER);
		store_be32(b + 8, subtype);
		buf_append_bytes(buf, b, 12);
	} else {
		b[4] = type;
		buf_append_bytes(buf, b, 5);
	}
}

static void buf_fill_ift_len(struct oc_text_buf *buf)
{
	if (!buf_error(buf) && buf->pos > 8)
		store_be32(buf->data + 8, buf->pos);
}

static void buf_fill_eap_len(struct oc_text_buf *buf)
{
	/* EAP length word is always at 0x16, and counts bytes from 0x14 */
	if (!buf_error(buf) && buf->pos > 0x18)
		store_be16(buf->data + 0x16, buf->pos - 0x14);
}

static void buf_append_avp(struct oc_text_buf *buf, uint32_t type, const void *bytes, int len)
{
	buf_append_be32(buf, type);
	buf_append_be16(buf, 0x8000);
	buf_append_be16(buf, len + 12);
	buf_append_be32(buf, VENDOR_JUNIPER2);
	buf_append_bytes(buf, bytes, len);
	if (len & 3) {
		uint32_t pad = 0;
		buf_append_bytes(buf, &pad, 4 - ( len & 3 ));
	}
}

static void buf_append_avp_be32(struct oc_text_buf *buf, uint32_t type, uint32_t val)
{
	uint32_t val_be;

	store_be32(&val_be, val);
	buf_append_avp(buf, type, &val_be, 4);
}

static void buf_append_avp_string(struct oc_text_buf *buf, uint32_t type, const char *str)
{
	buf_append_avp(buf, type, str, strlen(str));
}
#if 0

static void buf_append_tlv_be32(struct oc_text_buf *buf, uint16_t val, uint32_t data)
{
	unsigned char d[4];

	store_be32(d, data);

	buf_append_tlv(buf, val, 4, d);
}

static const char authpkt_head[] = { 0x00, 0x04, 0x00, 0x00, 0x00 };
static const char authpkt_tail[] = { 0xbb, 0x01, 0x00, 0x00, 0x00, 0x00 };

#define GRP_ATTR(g, a) (((g) << 16) | (a))

/* We behave like CSTP — create a linked list in vpninfo->cstp_options
 * with the strings containing the information we got from the server,
 * and oc_ip_info contains const copies of those pointers. */

static const char *add_option(struct openconnect_info *vpninfo, const char *opt,
			      const char *val, int val_len)
{
	struct oc_vpn_option *new = malloc(sizeof(*new));
	if (!new)
		return NULL;

	new->option = strdup(opt);
	if (!new->option) {
		free(new);
		return NULL;
	}
	if (val_len >= 0)
		new->value = strndup(val, val_len);
	else
		new->value = strdup(val);
	if (!new->value) {
		free(new->option);
		free(new);
		return NULL;
	}
	new->next = vpninfo->cstp_options;
	vpninfo->cstp_options = new;

	return new->value;
}

static int process_attr(struct openconnect_info *vpninfo, int group, int attr,
			unsigned char *data, int attrlen)
{
	char buf[80];
	int i;

	switch(GRP_ATTR(group, attr)) {
	case GRP_ATTR(6, 2):
		if (attrlen != 4) {
		badlen:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unexpected length %d for TLV %d/%d\n"),
				     attrlen, group, attr);
			return -EINVAL;
		}
		vpninfo->ip_info.mtu = load_be32(data);
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Received MTU %d from server\n"),
			     vpninfo->ip_info.mtu);
		break;

	case GRP_ATTR(2, 1):
		if (attrlen != 4)
			goto badlen;
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", data[0], data[1], data[2], data[3]);

		vpn_progress(vpninfo, PRG_DEBUG, _("Received DNS server %s\n"), buf);

		for (i = 0; i < 3; i++) {
			if (!vpninfo->ip_info.dns[i]) {
				vpninfo->ip_info.dns[i] = add_option(vpninfo, "DNS", buf, -1);
				break;
			}
		}
		break;

	case GRP_ATTR(2, 2):
		vpn_progress(vpninfo, PRG_DEBUG, _("Received DNS search domain %.*s\n"),
			     attrlen, (char *)data);
		vpninfo->ip_info.domain = add_option(vpninfo, "search", (char *)data, attrlen);
		if (vpninfo->ip_info.domain) {
			char *p = (char *)vpninfo->ip_info.domain;
			while ((p = strchr(p, ',')))
				*p = ' ';
		}
		break;

	case GRP_ATTR(1, 1):
		if (attrlen != 4)
			goto badlen;
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", data[0], data[1], data[2], data[3]);

		vpn_progress(vpninfo, PRG_DEBUG, _("Received internal IP address %s\n"), buf);
		vpninfo->ip_info.addr = add_option(vpninfo, "ipaddr", buf, -1);
		break;

	case GRP_ATTR(1, 2):
		if (attrlen != 4)
			goto badlen;
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", data[0], data[1], data[2], data[3]);

		vpn_progress(vpninfo, PRG_DEBUG, _("Received netmask %s\n"), buf);
		vpninfo->ip_info.netmask = add_option(vpninfo, "netmask", buf, -1);
		break;

	case GRP_ATTR(1, 3):
		if (attrlen != 4)
			goto badlen;
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", data[0], data[1], data[2], data[3]);

		vpn_progress(vpninfo, PRG_DEBUG, _("Received internal gateway address %s\n"), buf);
		/* Hm, what are we supposed to do with this? It's a tunnel;
		   having a gateway is meaningless. */
		add_option(vpninfo, "ipaddr", buf, -1);
		break;

	case GRP_ATTR(3, 3): {
		struct oc_split_include *inc;
		if (attrlen != 8)
			goto badlen;
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d/%d.%d.%d.%d",
			 data[0], data[1], data[2], data[3],
			 data[4], data[5], data[6], data[7]);
		vpn_progress(vpninfo, PRG_DEBUG, _("Received split include route %s\n"), buf);
		if (!data[4] && !data[5] && !data[6] && !data[7])
			break;
		inc = malloc(sizeof(*inc));
		if (inc) {
			inc->route = add_option(vpninfo, "split-include", buf, -1);
			if (inc->route) {
				inc->next = vpninfo->ip_info.split_includes;
				vpninfo->ip_info.split_includes = inc;
			} else
				free(inc);
		}
		break;
	}

	case GRP_ATTR(3, 4): {
		struct oc_split_include *exc;
		if (attrlen != 8)
			goto badlen;
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d/%d.%d.%d.%d",
			 data[0], data[1], data[2], data[3],
			 data[4], data[5], data[6], data[7]);
		vpn_progress(vpninfo, PRG_DEBUG, _("Received split exclude route %s\n"), buf);
		if (!data[4] && !data[5] && !data[6] && !data[7])
			break;
		exc = malloc(sizeof(*exc));
		if (exc) {
			exc->route = add_option(vpninfo, "split-exclude", buf, -1);
			if (exc->route) {
				exc->next = vpninfo->ip_info.split_excludes;
				vpninfo->ip_info.split_excludes = exc;
			} else
				free(exc);
		}
		break;
	}

	case GRP_ATTR(4, 1):
		if (attrlen != 4)
			goto badlen;
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", data[0], data[1], data[2], data[3]);

		vpn_progress(vpninfo, PRG_DEBUG, _("Received WINS server %s\n"), buf);

		for (i = 0; i < 3; i++) {
			if (!vpninfo->ip_info.nbns[i]) {
				vpninfo->ip_info.nbns[i] = add_option(vpninfo, "WINS", buf, -1);
				break;
			}
		}
		break;

	case GRP_ATTR(8, 1): {
		const char *enctype;

		if (attrlen != 1)
			goto badlen;
		if (data[0] == ENC_AES_128_CBC) {
			enctype = "AES-128";
			vpninfo->enc_key_len = 16;
		} else if (data[0] == ENC_AES_256_CBC) {
			enctype = "AES-256";
			vpninfo->enc_key_len = 32;
		} else
			enctype = "unknown";
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP encryption: 0x%02x (%s)\n"),
			      data[0], enctype);
		vpninfo->esp_enc = data[0];
		break;
	}

	case GRP_ATTR(8, 2): {
		const char *mactype;

		if (attrlen != 1)
			goto badlen;
		if (data[0] == HMAC_MD5) {
			mactype = "MD5";
			vpninfo->hmac_key_len = 16;
		} else if (data[0] == HMAC_SHA1) {
			mactype = "SHA1";
			vpninfo->hmac_key_len = 20;
		} else
			mactype = "unknown";
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP HMAC: 0x%02x (%s)\n"),
			      data[0], mactype);
		vpninfo->esp_hmac = data[0];
		break;
	}

	case GRP_ATTR(8, 3):
		if (attrlen != 1)
			goto badlen;
		vpninfo->esp_compr = data[0];
		vpninfo->dtls_compr = data[0] ? COMPR_LZO : 0;
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP compression: %d\n"), data[0]);
		break;

	case GRP_ATTR(8, 4):
		if (attrlen != 2)
			goto badlen;
		i = load_be16(data);
		udp_sockaddr(vpninfo, i);
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP port: %d\n"), i);
		break;

	case GRP_ATTR(8, 5):
		if (attrlen != 4)
			goto badlen;
		vpninfo->esp_lifetime_bytes = load_be32(data);
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP key lifetime: %u bytes\n"),
			     vpninfo->esp_lifetime_bytes);
		break;

	case GRP_ATTR(8, 6):
		if (attrlen != 4)
			goto badlen;
		vpninfo->esp_lifetime_seconds = load_be32(data);
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP key lifetime: %u seconds\n"),
			     vpninfo->esp_lifetime_seconds);
		break;

	case GRP_ATTR(8, 9):
		if (attrlen != 4)
			goto badlen;
		vpninfo->esp_ssl_fallback = load_be32(data);
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP to SSL fallback: %u seconds\n"),
			     vpninfo->esp_ssl_fallback);
		break;

	case GRP_ATTR(8, 10):
		if (attrlen != 4)
			goto badlen;
		vpninfo->esp_replay_protect = load_be32(data);
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP replay protection: %d\n"),
			     load_be32(data));
		break;

	case GRP_ATTR(7, 1):
		if (attrlen != 4)
			goto badlen;
		memcpy(&vpninfo->esp_out.spi, data, 4);
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP SPI (outbound): %x\n"),
			     load_be32(data));
		break;

	case GRP_ATTR(7, 2):
		if (attrlen != 0x40)
			goto badlen;
		/* data contains enc_key and hmac_key concatenated */
		memcpy(vpninfo->esp_out.enc_key, data, 0x40);
		vpn_progress(vpninfo, PRG_DEBUG, _("%d bytes of ESP secrets\n"),
			     attrlen);
		break;

	default:
		buf[0] = 0;
		for (i=0; i < 16 && i < attrlen; i++)
			sprintf(buf + strlen(buf), " %02x", data[i]);
		if (attrlen > 16)
			sprintf(buf + strlen(buf), "...");

		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Unknown TLV group %d attr %d len %d:%s\n"),
			       group, attr, attrlen, buf);
	}
	return 0;
}

static void put_len16(struct oc_text_buf *buf, int where)
{
	int len = buf->pos - where;

	store_be16(buf->data + where - 2, len);
}

static void put_len32(struct oc_text_buf *buf, int where)
{
	int len = buf->pos - where;

	store_be32(buf->data + where - 4, len);
}

#endif

/* XX: This is actually a lot of duplication with the CSTP version. */
void pulse_common_headers(struct openconnect_info *vpninfo, struct oc_text_buf *buf)
{
}

static int send_ift_packet(struct openconnect_info *vpninfo, struct oc_text_buf *buf)
{
	int ret;

	if (buf_error(buf)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error creating IF-T packet\n"));
		return buf_error(buf);
	}
	buf_fill_ift_len(buf);
	dump_buf_hex(vpninfo, PRG_DEBUG, '>', (void *)buf->data, buf->pos);
	ret = vpninfo->ssl_write(vpninfo, buf->data, buf->pos);
	if (ret != buf->pos) {
		if (ret >= 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Short write to IF-T/TLS\n"));
			ret = -EIO;
		}
		return ret;
	}
	return 0;
}

static void process_avp(struct openconnect_info *vpninfo, uint8_t flags,
		       uint32_t vendor, uint32_t code, void *p, int len)
{
	if (flags & AVP_VENDOR)
		vpn_progress(vpninfo, PRG_TRACE, _("AVP 0x%x/0x%x:\n"), vendor, code);
	else
		vpn_progress(vpninfo, PRG_TRACE, _("AVP %d:\n"), code);
	dump_buf_hex(vpninfo, PRG_TRACE, ' ', p, len);
}

/* RFC5281 §10 */
static int process_avps(struct openconnect_info *vpninfo, void *_p, int l)
{
	unsigned char *p = _p;
	uint32_t avp_code;
	uint32_t avp_len;
	uint32_t avp_vendor;
	uint8_t flags;

	while (l) {
		if (l < 8) {
		bad_len:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to parse AVP in Pulse packet; invalid length\n"));
			return -EINVAL;
		}
		avp_code = load_be32(p);
		avp_len = load_be32(p + 4) & 0xffffff;
		flags = p[4];

		if (avp_len > l || avp_len < 8)
			goto bad_len;
		if (flags & AVP_VENDOR) {
			if (l < 12 || avp_len < 12)
				goto bad_len;
			avp_vendor = load_be32(p + 8);
			p += 12;
			l -= 12;
			avp_len -= 12;
		} else {
			if (avp_len < 8)
				goto bad_len;
			avp_vendor = 0;
			p += 8;
			l -= 8;
			avp_len -= 8;
		}

		process_avp(vpninfo, flags, avp_vendor, avp_code, p, avp_len);
		avp_len = (avp_len + 3) & ~3;
		if (avp_len > l)
			return 0;
		p += avp_len;
		l -= avp_len;
	}
	return 0;
}

int pulse_connect(struct openconnect_info *vpninfo)
{
	int ret;
	struct oc_text_buf *reqbuf;
	unsigned char bytes[16384];

	/* XXX: We should do what cstp_connect() does to check that configuration
	   hasn't changed on a reconnect. */

	ret = openconnect_open_https(vpninfo);
	if (ret)
		return ret;

	reqbuf = buf_alloc();

	buf_append(reqbuf, "GET / HTTP/1.1\r\n");
	http_common_headers(vpninfo, reqbuf);
	buf_append(reqbuf, "Content-Type: EAP\r\n");
	buf_append(reqbuf, "Upgrade: IF-T/TLS 1.0\r\n");
	buf_append(reqbuf, "Content-Length: 0\r\n");
	buf_append(reqbuf, "\r\n");

	if (buf_error(reqbuf)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error creating Pulse connection request\n"));
		ret = buf_error(reqbuf);
		goto out;
	}
	if (vpninfo->dump_http_traffic)
		dump_buf(vpninfo, '>', reqbuf->data);

	ret = vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);
	if (ret < 0)
		goto out;

	ret = process_http_response(vpninfo, 1, NULL, reqbuf);
	if (ret < 0)
		goto out;

	if (ret != 101) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected %d result from server\n"),
			     ret);
		ret = -EINVAL;
		goto out;
	}

	/* IF-T version request. */
	buf_truncate(reqbuf);
	buf_append_ift_hdr(reqbuf, VENDOR_TCG, IFT_VERSION_REQUEST);
	/* min=1, max=2, preferred version=2 */
	buf_append_be32(reqbuf, 0x00010202);
	ret = send_ift_packet(vpninfo, reqbuf);
	if (ret)
		goto out;

	ret = vpninfo->ssl_read(vpninfo, (void *)bytes, sizeof(bytes));
	if (ret < 0)
		goto out;
	vpn_progress(vpninfo, PRG_TRACE,
		     _("Read %d bytes of SSL record\n"), ret);
	dump_buf_hex(vpninfo, PRG_TRACE, '<', (void *)bytes, ret);

	if (ret != 0x14 || (load_be32(bytes) & 0xffffff) != VENDOR_TCG ||
	    load_be32(bytes + 4) != IFT_VERSION_RESPONSE ||
	    load_be32(bytes + 8) != 0x14) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected response to IF-T version negotiation:\n"));
		dump_buf_hex(vpninfo, PRG_ERR, '<', (void *)bytes, ret);
		ret = -EINVAL;
		goto out;
	}
	vpn_progress(vpninfo, PRG_TRACE, _("IF-T version from server: %d\n"),
		     bytes[0x13]);

	/* Client information packet */
	buf_truncate(reqbuf);
	buf_append_ift_hdr(reqbuf, VENDOR_JUNIPER, 0x88);
	buf_append(reqbuf, "clientHostName=%s", vpninfo->localname);
	bytes[0] = 0;
	if (vpninfo->peer_addr && vpninfo->peer_addr->sa_family == AF_INET6) {
		struct sockaddr_in6 a;
		socklen_t l = sizeof(a);
		if (!getsockname(vpninfo->ssl_fd, &a, &l))
			inet_ntop(AF_INET6, &a.sin6_addr, (void *)bytes, sizeof(bytes));
	} else if (vpninfo->peer_addr && vpninfo->peer_addr->sa_family == AF_INET) {
		struct sockaddr_in a;
		socklen_t l = sizeof(a);
		if (!getsockname(vpninfo->ssl_fd, &a, &l))
			inet_ntop(AF_INET, &a.sin_addr, (void *)bytes, sizeof(bytes));
	}
	if (bytes[0])
		buf_append(reqbuf, " clientIp=%s", bytes);
	buf_append(reqbuf, "\n%c", 0);
	ret = send_ift_packet(vpninfo, reqbuf);
	if (ret)
		goto out;

	/* Await start of auth negotiations */
	ret = vpninfo->ssl_read(vpninfo, (void *)bytes, sizeof(bytes));
	if (ret < 0)
		goto out;
	vpn_progress(vpninfo, PRG_TRACE,
		     _("Read %d bytes of SSL record\n"), ret);
	dump_buf_hex(vpninfo, PRG_TRACE, '<', (void *)bytes, ret);

	if (ret != 0x14 || (load_be32(bytes) & 0xffffff) != VENDOR_TCG ||
	    load_be32(bytes + 4) != IFT_SASL_DATA ||
	    load_be32(bytes + 8) != 0x14 ||
	    load_be32(bytes + 0x10) != JUNIPER_1) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected SASL challenge:\n"));
		dump_buf_hex(vpninfo, PRG_ERR, '<', (void *)bytes, ret);
		ret = -EINVAL;
		goto out;
	}

	buf_truncate(reqbuf);
	buf_append_ift_hdr(reqbuf, VENDOR_TCG, IFT_SASL_RESULT);
	buf_append_eap_hdr(reqbuf, EAP_RESPONSE, 1, EAP_TYPE_IDENTITY, 0);
	buf_append(reqbuf, "anonymous");
	buf_fill_eap_len(reqbuf);
	ret = send_ift_packet(vpninfo, reqbuf);
	if (ret)
		goto out;

	/* Await start of auth negotiations */
	ret = vpninfo->ssl_read(vpninfo, (void *)bytes, sizeof(bytes));
	if (ret < 0)
		goto out;
	vpn_progress(vpninfo, PRG_TRACE,
		     _("Read %d bytes of SSL record\n"), ret);
	dump_buf_hex(vpninfo, PRG_TRACE, '<', (void *)bytes, ret);

	if (ret < 0x19 || (load_be32(bytes) & 0xffffff) != VENDOR_TCG ||
	    load_be32(bytes + 4) != IFT_SASL_DATA ||
	    load_be32(bytes + 8) < 0x14 ||
	    load_be32(bytes + 0x10) != JUNIPER_1 ||
	    bytes[0x14] != EAP_REQUEST ||
	    load_be16(bytes + 0x16) != ret - 0x14) {
	bad_eap:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected SASL challenge:\n"));
		dump_buf_hex(vpninfo, PRG_ERR, '<', (void *)bytes, ret);
		ret = -EINVAL;
		goto out;
	}

	/* Check requested EAP type */
	if (bytes[0x18] == 0x15) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Certificate auth via EAP-TTLS not yet supported for Pulse\n"));
		ret = -EINVAL;
		goto out;
	}
	if (ret < 0x20 || load_be32(bytes + 0x18) != EXPANDED_JUNIPER ||
	    load_be32(bytes + 0x1c) != 1)
		goto bad_eap;

	/* OK, we have an expanded Juniper/1 frame and we know the EAP length matches
	 * the actual length of what we read, as does the IF-T/TLS header. */
	ret = process_avps(vpninfo, bytes + 0x20, ret - 0x20);
	if (ret)
		goto out;

	/* Present the auth cookie */
	buf_truncate(reqbuf);
	buf_append_ift_hdr(reqbuf, VENDOR_TCG, IFT_SASL_RESULT);
	buf_append_eap_hdr(reqbuf, EAP_RESPONSE, bytes[0x15], EAP_TYPE_EXPANDED, 1);
	//buf_append_avp_string(reqbuf, 0xd5e, vpninfo->platname);
	buf_append_avp_string(reqbuf, 0xd70, vpninfo->useragent);
	buf_append_avp_string(reqbuf, 0xd53, vpninfo->cookie);
	buf_fill_eap_len(reqbuf);
	ret = send_ift_packet(vpninfo, reqbuf);
	if (ret)
		goto out;


	/* Await start of auth negotiations */
	ret = vpninfo->ssl_read(vpninfo, (void *)bytes, sizeof(bytes));
	if (ret < 0)
		goto out;
	vpn_progress(vpninfo, PRG_TRACE,
		     _("Read %d bytes of SSL record\n"), ret);
	dump_buf_hex(vpninfo, PRG_TRACE, '<', (void *)bytes, ret);

	if (ret < 0x19 || (load_be32(bytes) & 0xffffff) != VENDOR_TCG ||
	    load_be32(bytes + 4) != IFT_SASL_DATA ||
	    load_be32(bytes + 8) < 0x14 ||
	    load_be32(bytes + 0x10) != JUNIPER_1 ||
	    bytes[0x14] != EAP_REQUEST ||
	    load_be16(bytes + 0x16) != ret - 0x14)
		goto bad_eap;

	if (ret < 0x20 || load_be32(bytes + 0x18) != EXPANDED_JUNIPER ||
	    load_be32(bytes + 0x1c) != 1)
		goto bad_eap;

	// XXX: Check for validity
	ret = process_avps(vpninfo, bytes + 0x20, ret - 0x20);
	if (ret)
		goto out;


	/* Present the auth cookie */
	buf_truncate(reqbuf);
	buf_append_ift_hdr(reqbuf, VENDOR_TCG, IFT_SASL_RESULT);
	buf_append_eap_hdr(reqbuf, EAP_RESPONSE, bytes[0x15], EAP_TYPE_EXPANDED, 1);
	buf_fill_eap_len(reqbuf);
	ret = send_ift_packet(vpninfo, reqbuf);
	if (ret)
		goto out;

	while (0) {
		ret = vpninfo->ssl_read(vpninfo, (void *)bytes, 16384);
		if (ret < 0)
			goto out;
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Read %d bytes of SSL record\n"), ret);
		dump_buf_hex(vpninfo, PRG_TRACE, '<', (void *)bytes, ret);
		if (bytes[7] == 0x93) {
			bytes[ret] = 0;
			printf("%s", bytes + 16);
		}
	}
	ret = 0;
 out:
	if (ret)
		openconnect_close_https(vpninfo, 0);
	else {
		monitor_fd_new(vpninfo, ssl);
		monitor_read_fd(vpninfo, ssl);
		monitor_except_fd(vpninfo, ssl);
	}
	buf_free(reqbuf);

	free(vpninfo->cstp_pkt);
	vpninfo->cstp_pkt = NULL;
	vpninfo->ip_info.mtu= 1400;
	return ret;
}


int pulse_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable)
{
	int ret;
	int work_done = 0;

	if (vpninfo->ssl_fd == -1)
		goto do_reconnect;

	/* FIXME: The poll() handling here is fairly simplistic. Actually,
	   if the SSL connection stalls it could return a WANT_WRITE error
	   on _either_ of the SSL_read() or SSL_write() calls. In that case,
	   we should probably remove POLLIN from the events we're looking for,
	   and add POLLOUT. As it is, though, it'll just chew CPU time in that
	   fairly unlikely situation, until the write backlog clears. */
	while (readable) {
		/* Some servers send us packets that are larger than
		   negotiated MTU. We reserve some extra space to
		   handle that */
		int receive_mtu = MAX(16384, vpninfo->deflate_pkt_size ? : vpninfo->ip_info.mtu);
		int len, payload_len;

		if (!vpninfo->cstp_pkt) {
			vpninfo->cstp_pkt = malloc(sizeof(struct pkt) + receive_mtu);
			if (!vpninfo->cstp_pkt) {
				vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
				break;
			}
		}

		len = ssl_nonblock_read(vpninfo, &vpninfo->cstp_pkt->pulse.vendor, receive_mtu + 16);
		if (!len)
			break;
		if (len < 0)
			goto do_reconnect;
		if (len < 16) {
			vpn_progress(vpninfo, PRG_ERR, _("Short packet received (%d bytes)\n"), len);
			vpninfo->quit_reason = "Short packet received";
			return 1;
		}

		if (load_be32(&vpninfo->cstp_pkt->pulse.vendor) != VENDOR_JUNIPER ||
		    load_be32(&vpninfo->cstp_pkt->pulse.len) != len)
			goto unknown_pkt;

		vpninfo->ssl_times.last_rx = time(NULL);

		switch(load_be32(&vpninfo->cstp_pkt->pulse.type)) {
		case 4:
			payload_len = len - 16;
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Received data packet of %d bytes\n"),
				     payload_len);
			vpninfo->cstp_pkt->len = payload_len;
			queue_packet(&vpninfo->incoming_queue, vpninfo->cstp_pkt);
			vpninfo->cstp_pkt = NULL;
			work_done = 1;
			continue;

		default:
		unknown_pkt:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unknown Pulse packet\n"));
			dump_buf_hex(vpninfo, PRG_TRACE, '<', (void *)&vpninfo->cstp_pkt->pulse.vendor, len);
			continue;
		}
	}


	/* If SSL_write() fails we are expected to try again. With exactly
	   the same data, at exactly the same location. So we keep the
	   packet we had before.... */
	if (vpninfo->current_ssl_pkt) {
	handle_outgoing:
		vpninfo->ssl_times.last_tx = time(NULL);
		unmonitor_write_fd(vpninfo, ssl);


		vpn_progress(vpninfo, PRG_TRACE, _("Packet outgoing:\n"));
		dump_buf_hex(vpninfo, PRG_TRACE, '>',
			     (void *)&vpninfo->current_ssl_pkt->pulse.vendor,
			     vpninfo->current_ssl_pkt->len + 16);

		ret = ssl_nonblock_write(vpninfo,
					 &vpninfo->current_ssl_pkt->pulse.vendor,
					 vpninfo->current_ssl_pkt->len + 16);
		if (ret < 0) {
			do_reconnect:
			/* XXX: Do we have to do this or can we leave it open?
			 * Perhaps we could even reconnect asynchronously while
			 * the ESP is still running? */
#ifdef HAVE_ESP
			esp_shutdown(vpninfo);
#endif
			ret = ssl_reconnect(vpninfo);
			if (ret) {
				vpn_progress(vpninfo, PRG_ERR, _("Reconnect failed\n"));
				vpninfo->quit_reason = "Pulse reconnect failed";
				return ret;
			}
			vpninfo->dtls_need_reconnect = 1;
			return 1;
		} else if (!ret) {
#if 0 /* Not for Pulse yet */
			/* -EAGAIN: ssl_nonblock_write() will have added the SSL
			   fd to ->select_wfds if appropriate, so we can just
			   return and wait. Unless it's been stalled for so long
			   that DPD kicks in and we kill the connection. */
			switch (ka_stalled_action(&vpninfo->ssl_times, timeout)) {
			case KA_DPD_DEAD:
				goto peer_dead;
			case KA_REKEY:
				goto do_rekey;
			case KA_NONE:
				return work_done;
			default:
				/* This should never happen */
				;
			}
#else
			return work_done;
#endif
		}

		if (ret != vpninfo->current_ssl_pkt->len + 16) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("SSL wrote too few bytes! Asked for %d, sent %d\n"),
				     vpninfo->current_ssl_pkt->len + 8, ret);
			vpninfo->quit_reason = "Internal error";
			return 1;
		}
		/* Don't free the 'special' packets */
		if (vpninfo->current_ssl_pkt == vpninfo->deflate_pkt) {
			free(vpninfo->pending_deflated_pkt);
			vpninfo->pending_deflated_pkt = NULL;
		} else
			free(vpninfo->current_ssl_pkt);

		vpninfo->current_ssl_pkt = NULL;
	}

#if 0 /* Not understood for Pulse yet */
	if (vpninfo->owe_ssl_dpd_response) {
		vpninfo->owe_ssl_dpd_response = 0;
		vpninfo->current_ssl_pkt = (struct pkt *)&dpd_resp_pkt;
		goto handle_outgoing;
	}

	switch (keepalive_action(&vpninfo->ssl_times, timeout)) {
	case KA_REKEY:
	do_rekey:
		/* Not that this will ever happen; we don't even process
		   the setting when we're asked for it. */
		vpn_progress(vpninfo, PRG_INFO, _("CSTP rekey due\n"));
		if (vpninfo->ssl_times.rekey_method == REKEY_TUNNEL)
			goto do_reconnect;
		else if (vpninfo->ssl_times.rekey_method == REKEY_SSL) {
			ret = cstp_handshake(vpninfo, 0);
			if (ret) {
				/* if we failed rehandshake try establishing a new-tunnel instead of failing */
				vpn_progress(vpninfo, PRG_ERR, _("Rehandshake failed; attempting new-tunnel\n"));
				goto do_reconnect;
			}

			goto do_dtls_reconnect;
		}
		break;

	case KA_DPD_DEAD:
	peer_dead:
		vpn_progress(vpninfo, PRG_ERR,
			     _("CSTP Dead Peer Detection detected dead peer!\n"));
		goto do_reconnect;
	do_reconnect:
		ret = cstp_reconnect(vpninfo);
		if (ret) {
			vpn_progress(vpninfo, PRG_ERR, _("Reconnect failed\n"));
			vpninfo->quit_reason = "CSTP reconnect failed";
			return ret;
		}

	do_dtls_reconnect:
		/* succeeded, let's rekey DTLS, if it is not rekeying
		 * itself. */
		if (vpninfo->dtls_state > DTLS_SLEEPING &&
		    vpninfo->dtls_times.rekey_method == REKEY_NONE) {
			vpninfo->dtls_need_reconnect = 1;
		}

		return 1;

	case KA_DPD:
		vpn_progress(vpninfo, PRG_DEBUG, _("Send CSTP DPD\n"));

		vpninfo->current_ssl_pkt = (struct pkt *)&dpd_pkt;
		goto handle_outgoing;

	case KA_KEEPALIVE:
		/* No need to send an explicit keepalive
		   if we have real data to send */
		if (vpninfo->dtls_state != DTLS_CONNECTED &&
		    vpninfo->outgoing_queue.head)
			break;

		vpn_progress(vpninfo, PRG_DEBUG, _("Send CSTP Keepalive\n"));

		vpninfo->current_ssl_pkt = (struct pkt *)&keepalive_pkt;
		goto handle_outgoing;

	case KA_NONE:
		;
	}
#endif
	/* Service outgoing packet queue, if no DTLS */
	while (vpninfo->dtls_state != DTLS_CONNECTED &&
	       (vpninfo->current_ssl_pkt = dequeue_packet(&vpninfo->outgoing_queue))) {
		struct pkt *this = vpninfo->current_ssl_pkt;

		store_be32(&this->pulse.vendor, VENDOR_JUNIPER);
		store_be32(&this->pulse.type, 4);
		store_be32(&this->pulse.len, this->len + 16);
		this->pulse.zero = 0;

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Sending IF-T/TLS data packet of %d bytes\n"),
			     this->len);

		vpninfo->current_ssl_pkt = this;
		goto handle_outgoing;
	}

	/* Work is not done if we just got rid of packets off the queue */
	return work_done;
}

int pulse_bye(struct openconnect_info *vpninfo, const char *reason)
{
	/* Send a4c/89/len 0x10 */

	openconnect_close_https(vpninfo, 0);
	return 0;
}

#ifdef HAVE_ESPx
void pulse_esp_close(struct openconnect_info *vpninfo)
{
	/* Tell server to stop sending on ESP channel */
	queue_esp_control(vpninfo, 0);
	esp_close(vpninfo);
}

int pulse_esp_send_probes(struct openconnect_info *vpninfo)
{
	struct pkt *pkt;
	int pktlen, seq;

	if (vpninfo->dtls_fd == -1) {
		int fd = udp_connect(vpninfo);
		if (fd < 0)
			return fd;

		/* We are not connected until we get an ESP packet back */
		vpninfo->dtls_state = DTLS_SLEEPING;
		vpninfo->dtls_fd = fd;
		monitor_fd_new(vpninfo, dtls);
		monitor_read_fd(vpninfo, dtls);
		monitor_except_fd(vpninfo, dtls);
	}

	pkt = malloc(sizeof(*pkt) + 1 + vpninfo->pkt_trailer);
	if (!pkt)
		return -ENOMEM;

	for (seq=1; seq <= (vpninfo->dtls_state==DTLS_CONNECTED ? 1 : 2); seq++) {
		pkt->len = 1;
		pkt->data[0] = 0;
		pktlen = encrypt_esp_packet(vpninfo, pkt);
		if (pktlen >= 0)
			send(vpninfo->dtls_fd, (void *)&pkt->esp, pktlen, 0);
	}
	free(pkt);

	vpninfo->dtls_times.last_tx = time(&vpninfo->new_dtls_started);

	return 0;
};

int pulse_esp_catch_probe(struct openconnect_info *vpninfo, struct pkt *pkt)
{
	return (pkt->len == 1 && pkt->data[0] == 0);
}
#endif /* HAVE_ESP */
