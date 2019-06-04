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

	b[3] = 0;
	b[4] = 0;
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

static void buf_append_elem(struct oc_text_buf *buf, uint32_t type, const void *bytes, int len)
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

static void buf_append_elem_be32(struct oc_text_buf *buf, uint32_t type, uint32_t val)
{
	uint32_t val_be;

	store_be32(&val_be, val);
	buf_append_elem(buf, type, &val_be, 4);
}

static void buf_append_elem_string(struct oc_text_buf *buf, uint32_t type, const char *str)
{
	buf_append_elem(buf, type, str, strlen(str));
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

static int process_packet(struct openconnect_info *vpninfo, unsigned char *p, int l)
{
	uint32_t type;
	uint16_t flags; /* ? */
	uint16_t elem_len;

	while (l) {
		if (l < 12) {
		bad_len:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to parse Pulse packet; invalid length\n"));
			return -EINVAL;
		}
		elem_len = load_be16(p + 6);
		if (elem_len > l || elem_len < 12)
			goto bad_len;
		type = load_be32(p);
		flags = load_be16(p + 4);
		if (flags == 0x8000) {
			uint32_t vendor = load_be32(p + 8);
			vpn_progress(vpninfo, PRG_TRACE, _("Info 0x%x/0x%x:\n"), vendor, type);
			dump_buf_hex(vpninfo, PRG_TRACE, ' ', p + 12, elem_len - 12);
		}
		elem_len = (elem_len + 3) & ~3;
		if (elem_len > l)
			return 0;
		p += elem_len;
		l -= elem_len;
	}
	return 0;
}

int pulse_connect(struct openconnect_info *vpninfo)
{
	int ret, len, kmp, kmplen, group, check_len;
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
	/* min, max, preferred version all 0x01 */
	buf_append_be32(reqbuf, 0x00010101);
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
	ret = process_packet(vpninfo, bytes + 0x20, ret - 0x20);
	if (ret)
		goto out;

	/* Present the auth cookie */
	buf_truncate(reqbuf);
	buf_append_ift_hdr(reqbuf, VENDOR_TCG, IFT_SASL_RESULT);
	buf_append_eap_hdr(reqbuf, EAP_RESPONSE, 1, EAP_TYPE_EXPANDED, 1);
	buf_append_elem_be32(reqbuf, 0xd49, 3);
	buf_append_elem_be32(reqbuf, 0xd61, 0);
	buf_append_elem_string(reqbuf, 0xd53, "Windows");
	buf_append_elem_string(reqbuf, 0xd70, "Junos-Pulse/8.0.8.52215 (Windows 7)");
	buf_append_elem(reqbuf, 0xd63, "\xc5\xc9\xb2\x3b\x8e\xc1\x4e\x92\xbd\xed\x75\x1b\x36\x16\xb3\xc5", 16);
	buf_append_elem(reqbuf, 0xd64, "\x41\xc2\xb5\x23\xa9\xff\x4b\x48\xb7\x51\x56\x43\x7f\x15\xc2\xd7", 16);
	buf_append_elem_string(reqbuf, 0xd5f, "en-GB");
	buf_append_elem(reqbuf, 0xd6c, "\x52\x54\x00\x7c\x9b\x4c", 6);
	buf_append_elem_string(reqbuf, 0xd53, vpninfo->cookie);
	buf_fill_eap_len(reqbuf);
	process_packet(vpninfo, reqbuf->data + 0x20, reqbuf->pos - 0x20);
	ret = send_ift_packet(vpninfo, reqbuf);
	if (ret)
		goto out;

	while (1) {
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
	ret = -1;
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

	return ret;
}


int pulse_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable)
{
	int ret;
	int work_done = 0;

#if 0
	if (vpninfo->ssl_fd == -1)
		goto do_reconnect;

	/* FIXME: The poll() handling here is fairly simplistic. Actually,
	   if the SSL connection stalls it could return a WANT_WRITE error
	   on _either_ of the SSL_read() or SSL_write() calls. In that case,
	   we should probably remove POLLIN from the events we're looking for,
	   and add POLLOUT. As it is, though, it'll just chew CPU time in that
	   fairly unlikely situation, until the write backlog clears. */
	while (readable) {
		int len, kmp, kmplen, iplen;
		/* Some servers send us packets that are larger than
		   negitiated MTU. We reserve some estra space to
		   handle that */
		int receive_mtu = MAX(16384, vpninfo->ip_info.mtu);

		len = receive_mtu + vpninfo->pkt_trailer;
		if (!vpninfo->cstp_pkt) {
			vpninfo->cstp_pkt = malloc(sizeof(struct pkt) + len);
			if (!vpninfo->cstp_pkt) {
				vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
				break;
			}
			vpninfo->cstp_pkt->len = 0;
		}

		/*
		 * This protocol is horrid. There are encapsulations within
		 * encapsulations within encapsulations. Some of them entirely
		 * gratuitous.
		 *
		 * First there's the SSL records which are a natural part of
		 * using TLS as a transport. They appear to make no use of the
		 * packetisation which these provide.
		 *
		 * Then within the TLS data stream there are "records" preceded
		 * by a 16-bit little-endian length. It's not clear what these
		 * records represent; they appear to be entirely gratuitous and
		 * just need to be discarded. A record boundary sometimes falls
		 * right in the middle of a data packet; there's no apparent
		 * logic to it.
		 *
		 * Then there are the KMP packets themselves, each of which has
		 * a length field of its own. There can be multiple KMP packets
		 * in each of the above-mention "records", and as noted there
		 * even be *partial* KMP packets in each record.
		 *
		 * Finally, a KMP data packet may actually contain multiple IP
		 * packets, which need to be split apart by using the length
		 * field in the IP header. This is Legacy IP only, never IPv6
		 * for the Network Connect protocol.
		 */

		/* Until we pass it up the stack, we use cstp_pkt->len to show
		 * the amount of data received *including* the KMP header. */
		len = pulse_record_read(vpninfo,
				       vpninfo->cstp_pkt->pulse.kmp + vpninfo->cstp_pkt->len,
				       receive_mtu + 20 - vpninfo->cstp_pkt->len);
		if (!len)
			break;
		else if (len < 0) {
			if (vpninfo->quit_reason)
				return len;
			goto do_reconnect;
		}
		vpninfo->cstp_pkt->len += len;
		vpninfo->ssl_times.last_rx = time(NULL);
		if (vpninfo->cstp_pkt->len < 20)
			continue;

	next_kmp:
		/* Now we have a KMP header. It might already have been there */
		kmp = load_be16(vpninfo->cstp_pkt->pulse.kmp + 6);
		kmplen = load_be16(vpninfo->cstp_pkt->pulse.kmp + 18);
		if (len == vpninfo->cstp_pkt->len)
			vpn_progress(vpninfo, PRG_DEBUG, _("Incoming KMP message %d of size %d (got %d)\n"),
				     kmp, kmplen, vpninfo->cstp_pkt->len - 20);
		else
			vpn_progress(vpninfo, PRG_DEBUG, _("Continuing to process KMP message %d now size %d (got %d)\n"),
				     kmp, kmplen, vpninfo->cstp_pkt->len - 20);

		switch (kmp) {
		case 300:
		next_ip:
			/* Need at least 6 bytes of payload to check the IP packet length */
			if (vpninfo->cstp_pkt->len < 26)
				continue;
			switch(vpninfo->cstp_pkt->data[0] >> 4) {
			case 4:
				iplen = load_be16(vpninfo->cstp_pkt->data + 2);
				break;
			case 6:
				iplen = load_be16(vpninfo->cstp_pkt->data + 4) + 40;
				break;
			default:
			badiplen:
				vpn_progress(vpninfo, PRG_ERR,
					     _("Unrecognised data packet\n"));
				goto unknown_pkt;
			}

			if (!iplen || iplen > receive_mtu || iplen > kmplen)
				goto badiplen;

			if (iplen > vpninfo->cstp_pkt->len - 20)
				continue;

			work_done = 1;
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Received uncompressed data packet of %d bytes\n"),
				     iplen);

			/* If there's nothing after the IP packet, and it's the last (or
			 * only) packet in this KMP300 so we don't need to keep the KMP
			 * header either, then just queue it. */
			if (iplen == kmplen && iplen == vpninfo->cstp_pkt->len - 20) {
				vpninfo->cstp_pkt->len = iplen;
				queue_packet(&vpninfo->incoming_queue, vpninfo->cstp_pkt);
				vpninfo->cstp_pkt = NULL;
				continue;
			}

			/* OK, we have a whole packet, and we have stuff after it */
			queue_new_packet(&vpninfo->incoming_queue, vpninfo->cstp_pkt->data, iplen);
			kmplen -= iplen;
			if (kmplen) {
				/* Still data packets to come in this KMP300 */
				store_be16(vpninfo->cstp_pkt->pulse.kmp + 18, kmplen);
				vpninfo->cstp_pkt->len -= iplen;
				if (vpninfo->cstp_pkt->len > 20)
					memmove(vpninfo->cstp_pkt->data,
						vpninfo->cstp_pkt->data + iplen,
						vpninfo->cstp_pkt->len - 20);
				goto next_ip;
			}
			/* We have depleted the KMP300, and there are more bytes from
			 * the next KMP message in the buffer. Move it up and process it */
			memmove(vpninfo->cstp_pkt->pulse.kmp,
				vpninfo->cstp_pkt->data + iplen,
				vpninfo->cstp_pkt->len - iplen - 20);
			vpninfo->cstp_pkt->len -= (iplen + 20);
			goto next_kmp;

		case 302:
			/* Should never happen; if it does we'll have to cope */
			if (kmplen > receive_mtu)
				goto unknown_pkt;
			/* Probably never happens. We need it in its own record.
			 * If I fix pulse_receive_espkeys() not to reuse cstp_pkt
			 * we can stop doing this. */
			if (vpninfo->cstp_pkt->len != kmplen + 20)
				goto unknown_pkt;
			ret = pulse_receive_espkeys(vpninfo, kmplen);
			work_done = 1;
			break;

		default:
		unknown_pkt:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unknown KMP message %d of size %d:\n"), kmp, kmplen);
			dump_buf_hex(vpninfo, PRG_ERR, '<', vpninfo->cstp_pkt->pulse.kmp,
				     vpninfo->cstp_pkt->len);
			if (kmplen + 20 != vpninfo->cstp_pkt->len)
				vpn_progress(vpninfo, PRG_DEBUG,
					     _(".... + %d more bytes unreceived\n"),
					     kmplen + 20 - vpninfo->cstp_pkt->len);
			vpninfo->quit_reason = "Unknown packet received";
			return 1;
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
			     vpninfo->current_ssl_pkt->pulse.rec,
			     vpninfo->current_ssl_pkt->len + 22);

		ret = ssl_nonblock_write(vpninfo,
					 vpninfo->current_ssl_pkt->pulse.rec,
					 vpninfo->current_ssl_pkt->len + 22);
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
				vpninfo->quit_reason = "pulse reconnect failed";
				return ret;
			}
			vpninfo->dtls_need_reconnect = 1;
			return 1;
		} else if (!ret) {
#if 0 /* Not for Juniper yet */
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

		if (ret != vpninfo->current_ssl_pkt->len + 22) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("SSL wrote too few bytes! Asked for %d, sent %d\n"),
				     vpninfo->current_ssl_pkt->len + 22, ret);
			vpninfo->quit_reason = "Internal error";
			return 1;
		}
		/* Don't free the 'special' packets */
		if (vpninfo->current_ssl_pkt == vpninfo->deflate_pkt) {
			free(vpninfo->pending_deflated_pkt);
		} else if (vpninfo->current_ssl_pkt == &esp_enable_pkt) {
			/* Only set the ESP state to connected and actually start
			   sending packets on it once the enable message has been
			   *sent* over the TCP channel. */
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Sent ESP enable control packet\n"));
			vpninfo->dtls_state = DTLS_CONNECTED;
			work_done = 1;
		} else {
			free(vpninfo->current_ssl_pkt);
		}
		vpninfo->current_ssl_pkt = NULL;
	}

#if 0 /* Not understood for Juniper yet */
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
		if (vpninfo->dtls_state != DTLS_CONNECTED && vpninfo->outgoing_queue)
			break;

		vpn_progress(vpninfo, PRG_DEBUG, _("Send CSTP Keepalive\n"));

		vpninfo->current_ssl_pkt = (struct pkt *)&keepalive_pkt;
		goto handle_outgoing;

	case KA_NONE:
		;
	}
#endif
	/* Queue the ESP enable message. We will start sending packets
	 * via ESP once the enable message has been *sent* over the
	 * TCP channel. Assign it directly to current_ssl_pkt so that
	 * we can use it in-place and match against it above. */
	if (vpninfo->dtls_state == DTLS_CONNECTING) {
		vpninfo->current_ssl_pkt = (struct pkt *)&esp_enable_pkt;
		goto handle_outgoing;
	}

	vpninfo->current_ssl_pkt = dequeue_packet(&vpninfo->pulse_control_queue);
	if (vpninfo->current_ssl_pkt)
		goto handle_outgoing;

	/* Service outgoing packet queue, if no DTLS */
	while (vpninfo->dtls_state != DTLS_CONNECTED &&
	       (vpninfo->current_ssl_pkt = dequeue_packet(&vpninfo->outgoing_queue))) {
		struct pkt *this = vpninfo->current_ssl_pkt;

		/* Little-endian overall record length */
		store_le16(this->pulse.rec, (this->len + 20));
		memcpy(this->pulse.kmp, data_hdr, 18);
		/* Big-endian length in KMP message header */
		store_be16(this->pulse.kmp + 18, this->len);

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Sending uncompressed data packet of %d bytes\n"),
			     this->len);

		goto handle_outgoing;
	}
#endif
	/* Work is not done if we just got rid of packets off the queue */
	return work_done;
}

int pulse_bye(struct openconnect_info *vpninfo, const char *reason)
{
	char *orig_path;
	char *res_buf=NULL;
	int ret;

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
