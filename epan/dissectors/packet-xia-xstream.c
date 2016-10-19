/* packet-xip-xstream.c
 * Routines for XStream dissection
 * Copyright 2016 Dan Barrett <barrettd@cs.cmu.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/*
 * More information about XIA can be found here:
 *  https://www.cs.cmu.edu/~xia/
 *  https://github.com/XIAProject/xia-core
 *  https://github.com/AltraMayor/XIA-for-Linux/wiki
 */
#include <config.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <wsutil/str_util.h>
#include <epan/ip_opts.h>
#include "packet-xip.h"

void proto_reg_handoff_xstream(void);
void proto_register_xstream(void);

/* If set, do not put the Xstream timestamp information on the summary line */
static gboolean xstream_ignore_timestamps = TRUE;

static int proto_xstream = -1;
static int hf_xstream_next_hdr = -1;
static int hf_xstream_off = -1;
static int hf_xstream_flags = -1;
static int hf_xstream_seqno = -1;
static int hf_xstream_ackno = -1;
static int hf_xstream_flags_res1 = -1;
static int hf_xstream_flags_res2 = -1;
static int hf_xstream_flags_res3 = -1;
static int hf_xstream_flags_res4 = -1;
static int hf_xstream_flags_res5 = -1;
static int hf_xstream_flags_res6 = -1;
static int hf_xstream_flags_res7 = -1;
static int hf_xstream_flags_ns = -1;
static int hf_xstream_flags_cwr = -1;
static int hf_xstream_flags_ecn = -1;
static int hf_xstream_flags_unused = -1;
static int hf_xstream_flags_ack = -1;
static int hf_xstream_flags_push = -1;
static int hf_xstream_flags_reset = -1;
static int hf_xstream_flags_syn = -1;
static int hf_xstream_flags_fin = -1;
static int hf_xstream_flags_str = -1;
static int hf_xstream_win = -1;
static int hf_xstream_options = -1;
static int hf_xstream_option_kind = -1;
static int hf_xstream_option_len = -1;
static int hf_xstream_option_mss = -1;
static int hf_xstream_option_mss_val = -1;
static int hf_xstream_option_wscale_shift = -1;
static int hf_xstream_option_wscale_multiplier = -1;
static int hf_xstream_option_timestamp_tsval = -1;
static int hf_xstream_option_timestamp_tsecr = -1;
static int hf_xstream_option_padding = -1;
static int hf_xstream_option_migrate = -1;
static int hf_xstream_option_migrate_len = -1;
static int hf_xstream_option_migrate_count = -1;
static int hf_xstream_option_migrate_src = -1;
static int hf_xstream_option_migrate_dst = -1;
static int hf_xstream_option_migrate_ts= -1;
static int hf_xstream_option_migrate_signature = -1;
static int hf_xstream_option_migrate_key = -1;
static int hf_xstream_option_migrate_ack = -1;
static int hf_xstream_option_type = -1;
static int hf_xstream_option_type_copy = -1;
static int hf_xstream_option_type_class = -1;
static int hf_xstream_option_type_number = -1;

static dissector_handle_t xstream_handle;

static expert_field ei_xstream_opt_len_invalid = EI_INIT;
static expert_field ei_xstream_option_wscale_shift_invalid = EI_INIT;
static expert_field ei_xstream_short_segment = EI_INIT;
static expert_field ei_xstream_ack_nonzero = EI_INIT;
static expert_field ei_xstream_suboption_malformed = EI_INIT;
static expert_field ei_xstream_invalid_len = EI_INIT;
static expert_field ei_xstream_next_header = EI_INIT;
static expert_field ei_ip_nop = EI_INIT;


static gint ett_xstream = -1;
static gint ett_xstream_flags = -1;
static gint ett_xstream_options = -1;
static gint ett_xstream_option_type = -1;
static gint ett_xstream_option_timestamp = -1;
static gint ett_xstream_option_mss = -1;
static gint ett_xstream_option_wscale = -1;
static gint ett_xstream_option_migrate = -1;
static gint ett_xstream_option_migrate_payload = -1;
static gint ett_xstream_option_migrate_sig = -1;
static gint ett_xstream_option_migrate_key = -1;
static gint ett_xstream_option_migrate_ack = -1;
static gint ett_xstream_option_other = -1;
static gint ett_xstream_unknown_opt = -1;


/* size of the xstream header with no options */
#define XSTREAM_MIN_LENGTH 16

/* offsets in bytes */
#define XSTREAM_NXTH  0
#define XSTREAM_OFF   1
#define XSTREAM_FLAGS 2
#define XSTREAM_SEQNO 4
#define XSTREAM_ACKNO 8
#define XSTREAM_WIN   12
#define XSTREAM_OPTS  16

/* Xstream options */
#define XSTREAM_OPT_EOL         0
#define XSTREAM_OPT_NOP         1
#define XSTREAM_OPT_MSS         2
#define XSTREAM_OPT_WINDOW      3
#define XSTREAM_OPT_TIMESTAMP   8
#define XSTREAM_OPT_MIGRATE     50
#define XSTREAM_OPT_MIGRATE_ACK 51

/* Xstream option lengths */
#define XSTREAM_OLEN_MSS             4
#define XSTREAM_OLEN_WSCALE          4
#define XSTREAM_OLEN_TIMESTAMP       12
#define XSTREAM_OLEN_MIGRATE_MIN     8
#define XSTREAM_OLEN_MIGRATE_ACK_MIN 8

static const value_string xstream_option_kind_vs[] = {
    {XSTREAM_OPT_EOL, "End of Option List"},
    {XSTREAM_OPT_NOP, "No-Operation"},
    {XSTREAM_OPT_MSS, "Maximum Segment Size"},
    {XSTREAM_OPT_WINDOW, "Window Scale"},
    {XSTREAM_OPT_TIMESTAMP, "Time Stamp Option"},
	{XSTREAM_OPT_MIGRATE, "Migration"},
	{XSTREAM_OPT_MIGRATE_ACK, "Migration ACK"},
    {0, NULL}
};

static value_string_ext xstream_option_kind_vs_ext = VALUE_STRING_EXT_INIT(xstream_option_kind_vs);

/* Xstream Flags */
#define TH_FIN    0x01
#define TH_SYN    0x02
#define TH_RST    0x04
#define TH_PUSH   0x08
#define TH_ACK    0x10
#define TH_UNUSED 0x20  /* FIXME: we don't have anything from here down... */
#define TH_ECE    0x40
#define TH_CWR    0x80
#define TH_NS     0x100
#define TH_RES1   0x200
#define TH_RES2   0x400
#define TH_RES3   0x800
#define TH_RES4   0x1000
#define TH_RES5   0x2000
#define TH_RES6   0x4000
#define TH_RES7   0x8000
#define TH_RESERVED (TH_RES1|TH_RES2|TH_RES3|TH_RES4|TH_RES5|TH_RES6|TH_RES7)

static const char *
xstream_flags_to_str(gint16 f)
{
    static const char flags[][7] = {"FIN", "SYN", "RST", "PSH", "ACK", "Unused", "ECN", "CWR", "NS"};
    const int maxlength = 64; /* upper bounds, max 53B: 8 * 3 + 2 + strlen("Reserved") + 9 * 2 + 1 */
    char *pbuf;
    const char *buf;
    int i;

    buf = pbuf = (char *) wmem_alloc(wmem_packet_scope(), maxlength);
    *pbuf = '\0';

    for (i = 0; i < 9; i++) {
        if (f & (1 << i)) {
            if (buf[0])
                pbuf = g_stpcpy(pbuf, ", ");
            pbuf = g_stpcpy(pbuf, flags[i]);
        }
    }

    if (f & TH_RESERVED) {
        if (buf[0])
            pbuf = g_stpcpy(pbuf, ", ");
        g_stpcpy(pbuf, "Reserved");
    }

    if (buf[0] == '\0')
        buf = "<None>";

    return buf;
}

static const char *
xstream_flags_to_str_first_letter(gint16 flags)
{
    wmem_strbuf_t *buf = wmem_strbuf_new(wmem_packet_scope(), "");
    unsigned i;
    const unsigned flags_count = 16;
    const char first_letters[] = "RRRRRRRNCEUAPRSF";

    /* upper 7 bytes are marked as reserved ('R'). */
    for (i = 0; i < flags_count; i++) {
        if (((flags >> (flags_count - 1 - i)) & 1)) {
            wmem_strbuf_append_c(buf, first_letters[i]);
       } else {
            wmem_strbuf_append(buf, ".");
       }
   }

    return wmem_strbuf_finalize(buf);
}


static void
xstream_info_append_uint(packet_info *pinfo, const char *abbrev, guint32 val)
{
    col_append_str_uint(pinfo->cinfo, COL_INFO, abbrev, val, " ");
}

static void
dissect_xstream_opt_mss(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint optlen, packet_info *pinfo, proto_tree *opt_tree, void *data _U_)
{
    proto_item *item;
    proto_tree *exp_tree;
    guint16 mss;
	guint16 len;

    mss = tvb_get_ntohs(tvb, offset + 2);
	len = tvb_get_guint8(tvb, offset + 1) << 2;

	// FIXME: add error handler for incorrect len
    item = proto_tree_add_none_format(opt_tree, hf_xstream_option_mss, tvb, offset, optlen, "%s: %u bytes", optp->name, mss);
    exp_tree = proto_item_add_subtree(item, ett_xstream_option_mss);
    proto_tree_add_item(exp_tree, hf_xstream_option_kind, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_uint_format_value(exp_tree, hf_xstream_option_len, tvb, offset, 1, len, "%u bytes (%u)", len, len >> 2);
	offset += 1;
    proto_tree_add_item(exp_tree, hf_xstream_option_mss_val, tvb, offset, 2, ENC_BIG_ENDIAN);
    xstream_info_append_uint(pinfo, "MSS", mss);
}

/* The window scale extension is defined in RFC 1323 */
static void
dissect_xstream_opt_wscale(const ip_tcp_opt *optp _U_, tvbuff_t *tvb,
    int offset, guint optlen _U_, packet_info *pinfo, proto_tree *opt_tree, void *data _U_)
{
    guint8 val;
    guint32 shift;
    proto_item *wscale_pi, *shift_pi, *gen_pi;
    proto_tree *wscale_tree;
	guint16 len;

	len = tvb_get_guint8(tvb, offset + 1) << 2;

    wscale_tree = proto_tree_add_subtree(opt_tree, tvb, offset, 4, ett_xstream_option_wscale, &wscale_pi, "Window scale: ");

    proto_tree_add_item(wscale_tree, hf_xstream_option_kind, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
	proto_tree_add_uint_format_value(wscale_tree, hf_xstream_option_len, tvb, offset, 1, len, "%u bytes (%u)", len, len >> 2);
    offset += 1;
	proto_tree_add_item(wscale_tree, hf_xstream_option_padding, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
    shift_pi = proto_tree_add_item_ret_uint(wscale_tree, hf_xstream_option_wscale_shift, tvb, offset, 1, ENC_BIG_ENDIAN, &shift);
    if (shift > 14) {
        /* RFC 1323: "If a Window Scale option is received with a shift.cnt
         * value exceeding 14, the TCP should log the error but use 14 instead
         * of the specified value." */
        shift = 14;
        expert_add_info(pinfo, shift_pi, &ei_xstream_option_wscale_shift_invalid);
    }

    gen_pi = proto_tree_add_uint(wscale_tree, hf_xstream_option_wscale_multiplier, tvb,
                                 offset, 1, 1 << shift);
    PROTO_ITEM_SET_GENERATED(gen_pi);
    val = tvb_get_guint8(tvb, offset);

    proto_item_append_text(wscale_pi, "%u (multiply by %u)", val, 1 << shift);

    xstream_info_append_uint(pinfo, "WS", 1 << shift);
}

static void
dissect_xstream_opt_migrate(const ip_tcp_opt *optp _U_, tvbuff_t *tvb,
    int offset, guint optlen _U_, packet_info *pinfo, proto_tree *opt_tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *m_tree, *payload_tree, *sig_tree, *key_tree;
	proto_tree *src_tree, *dst_tree, *ts_tree;
	guint16 len;
	guint16 cnt;
    int start;
	guint16 size, section_size;

    start = offset;
	len = tvb_get_guint8(tvb, offset + 1) << 2;

    m_tree = proto_tree_add_subtree(opt_tree, tvb, offset, len, ett_xstream_option_migrate, &ti, optp->name);

    proto_tree_add_item(m_tree, hf_xstream_option_kind, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

	proto_tree_add_uint_format_value(m_tree, hf_xstream_option_len, tvb, offset, 1, len,
        "%u bytes (%u)", len, len >> 2);
    offset += 1;

	// FIXME: these will need to do network byte ordering
	proto_tree_add_item(m_tree, hf_xstream_option_migrate_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	// payload
	section_size = tvb_get_letohs(tvb, offset);
	payload_tree = proto_tree_add_subtree(m_tree, tvb, offset, section_size + 2, ett_xstream_option_migrate_payload, NULL, "Payload");
	proto_tree_add_item(payload_tree, hf_xstream_option_migrate_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	cnt = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(payload_tree, hf_xstream_option_migrate_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	if (cnt == 3) {
		size = tvb_get_letohs(tvb, offset);
		src_tree = proto_tree_add_subtree(payload_tree, tvb, offset, size + 2, ett_xstream_option_migrate_payload, NULL, "Source DAG");
		proto_tree_add_item(src_tree, hf_xstream_option_migrate_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item(src_tree, hf_xstream_option_migrate_src, tvb, offset, size, ENC_ASCII);
		offset += size;
	}

	size = tvb_get_letohs(tvb, offset);
	dst_tree = proto_tree_add_subtree(payload_tree, tvb, offset, size + 2, ett_xstream_option_migrate_payload, NULL, "Destination DAG");
	proto_tree_add_item(dst_tree, hf_xstream_option_migrate_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(dst_tree, hf_xstream_option_migrate_dst, tvb, offset, size, ENC_ASCII);
	offset += size;

	size = tvb_get_letohs(tvb, offset);
	ts_tree = proto_tree_add_subtree(payload_tree, tvb, offset, size + 2, ett_xstream_option_migrate_payload, NULL, "Timestamp");
	proto_tree_add_item(ts_tree, hf_xstream_option_migrate_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(ts_tree, hf_xstream_option_migrate_ts, tvb, offset, size, ENC_ASCII);
	offset += size;

	// signature
	size = tvb_get_letohs(tvb, offset);
	sig_tree = proto_tree_add_subtree(m_tree, tvb, offset, size + 2, ett_xstream_option_migrate_sig, NULL, "Signature");
	proto_tree_add_item(sig_tree, hf_xstream_option_migrate_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(sig_tree, hf_xstream_option_migrate_signature, tvb, offset, size, ENC_NA);
	offset += size;

	// public key
	size = tvb_get_letohs(tvb, offset);
	key_tree = proto_tree_add_subtree(m_tree, tvb, offset, size + 2, ett_xstream_option_migrate_key, NULL, "Public Key");
	proto_tree_add_item(key_tree, hf_xstream_option_migrate_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(key_tree, hf_xstream_option_migrate_key, tvb, offset, size, ENC_ASCII);
	offset += size;

	if (offset != len) {
		proto_tree_add_item(m_tree, hf_xstream_option_padding, tvb, offset, start + len - offset, ENC_NA);
	}


	if (0) {
		// FIXME: use real error here, not dummy for pinfo use
        expert_add_info(pinfo, ti, &ei_xstream_option_wscale_shift_invalid);
    }
}

static void
dissect_xstream_opt_timestamp(const ip_tcp_opt *optp _U_, tvbuff_t *tvb,
    int offset, guint optlen _U_, packet_info *pinfo, proto_tree *opt_tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *ts_tree;
    guint32 ts_val, ts_ecr;
	guint16 len;

	len = tvb_get_guint8(tvb, offset + 1) << 2;

    ts_tree = proto_tree_add_subtree(opt_tree, tvb, offset, XSTREAM_OLEN_TIMESTAMP,
        ett_xstream_option_timestamp, &ti, "Timestamps: ");

    proto_tree_add_item(ts_tree, hf_xstream_option_kind, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

	proto_tree_add_uint_format_value(ts_tree, hf_xstream_option_len, tvb, offset, 1, len,
        "%u bytes (%u)", len, len >> 2);
    offset += 1;

	// zeros
	proto_tree_add_item(ts_tree, hf_xstream_option_padding, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

    proto_tree_add_item_ret_uint(ts_tree, hf_xstream_option_timestamp_tsval, tvb, offset,
                        4, ENC_BIG_ENDIAN, &ts_val);
    offset += 4;

    proto_tree_add_item_ret_uint(ts_tree, hf_xstream_option_timestamp_tsecr, tvb, offset,
                        4, ENC_BIG_ENDIAN, &ts_ecr);
    /* offset += 4; */

    proto_item_append_text(ti, "TSval %u, TSecr %u", ts_val, ts_ecr);
    if (xstream_ignore_timestamps == FALSE) {
        xstream_info_append_uint(pinfo, "TSval", ts_val);
        xstream_info_append_uint(pinfo, "TSecr", ts_ecr);
    }
}



static const ip_tcp_opt xstreamopts[] = {
    {
        XSTREAM_OPT_EOL,
        "End of Option List (EOL)",
        NULL,
        OPT_LEN_NO_LENGTH,
        0,
        NULL,
    },
    {
        XSTREAM_OPT_NOP,
        "No-Operation (NOP)",
        NULL,
        OPT_LEN_NO_LENGTH,
        0,
        NULL,
    },
    {
        XSTREAM_OPT_MSS,
        "Maximum segment size",
        NULL,
        OPT_LEN_FIXED_LENGTH,
        XSTREAM_OLEN_MSS,
        dissect_xstream_opt_mss
    },
    {
        XSTREAM_OPT_WINDOW,
        "Window scale",
        NULL,
        OPT_LEN_FIXED_LENGTH,
        XSTREAM_OLEN_WSCALE,
        dissect_xstream_opt_wscale
    },
    {
        XSTREAM_OPT_TIMESTAMP,
        "Timestamps",
        NULL,
        OPT_LEN_FIXED_LENGTH,
        XSTREAM_OLEN_TIMESTAMP,
        dissect_xstream_opt_timestamp
    },
	{
		XSTREAM_OPT_MIGRATE,
		"Migration",
		NULL,
		OPT_LEN_VARIABLE_LENGTH,
		XSTREAM_OLEN_MIGRATE_MIN,
		dissect_xstream_opt_migrate
	},
	{
		XSTREAM_OPT_MIGRATE_ACK,
		"Migration Ack",
		NULL,
		OPT_LEN_VARIABLE_LENGTH,
		XSTREAM_OLEN_MIGRATE_ACK_MIN,
		dissect_xstream_opt_migrate
	}
};

#define N_XSTREAM_OPTS  array_length(xstreamopts)

static ip_tcp_opt_type XSTREAM_OPT_TYPES = {
    &hf_xstream_option_type,
    &ett_xstream_option_type,
    &hf_xstream_option_type_copy,
    &hf_xstream_option_type_class,
    &hf_xstream_option_type_number
};

static void
dissect_ipopt_type(tvbuff_t *tvb, int offset, proto_tree *tree, ip_tcp_opt_type* opttypes)
{
  proto_tree *type_tree;
  proto_item *ti;

  ti = proto_tree_add_item(tree, *opttypes->phf_opt_type, tvb, offset, 1, ENC_NA);
  type_tree = proto_item_add_subtree(ti, *opttypes->pett_opt_type);
  proto_tree_add_item(type_tree, *opttypes->phf_opt_type_copy, tvb, offset, 1, ENC_NA);
  proto_tree_add_item(type_tree, *opttypes->phf_opt_type_class, tvb, offset, 1, ENC_NA);
  proto_tree_add_item(type_tree, *opttypes->phf_opt_type_number, tvb, offset, 1, ENC_NA);
}

void
dissect_xstream_options(tvbuff_t *tvb, int offset, guint length,
                       const ip_tcp_opt *opttab, int nopts, int eol,
                       ip_tcp_opt_type* opttypes, expert_field* ei_bad,
                       packet_info *pinfo, proto_tree *opt_tree,
                       proto_item *opt_item, void * data)
{
  guchar            opt;
  const ip_tcp_opt *optp;
  opt_len_type      len_type;
  unsigned int      optlen;
  const char       *name;
  void            (*dissect)(const struct ip_tcp_opt *, tvbuff_t *,
                             int, guint, packet_info *, proto_tree *,
                             void *);
  guint             len, nop_count = 0;

  while (length > 0) {
    opt = tvb_get_guint8(tvb, offset);
    for (optp = &opttab[0]; optp < &opttab[nopts]; optp++) {
      if (optp->optcode == opt)
        break;
    }
    if (optp == &opttab[nopts]) {
      /* We assume that the only OPT_LEN_NO_LENGTH options are EOL and NOP options,
         so that we can treat unknown options as OPT_LEN_VARIABLE_LENGTH with a
         minimum of 2, and at least be able to move on to the next option
         by using the length in the option. */
      optp = NULL;  /* indicate that we don't know this option */
      len_type = OPT_LEN_VARIABLE_LENGTH;
      optlen = 2;
      name = wmem_strdup_printf(wmem_packet_scope(), "Unknown (0x%02x)", opt);
      dissect = NULL;
      nop_count = 0;
    } else {
      len_type = optp->len_type;
      optlen = optp->optlen;
      name = optp->name;
      dissect = optp->dissect;
      if (opt_item && len_type == OPT_LEN_NO_LENGTH && optlen == 0 && opt == 1 &&
         (nop_count == 0 || offset % 4)) { /* opt 1 = NOP in both IP and TCP */
        /* Count number of NOP in a row within a uint32 */
        nop_count++;
      } else {
        nop_count = 0;
      }
    }
    --length;      /* account for type byte */
    if (len_type != OPT_LEN_NO_LENGTH) {
      /* Option has a length. Is it in the packet? */
      if (length == 0) {
        /* Bogus - packet must at least include option code byte and
           length byte! */
        proto_tree_add_expert_format(opt_tree, pinfo, ei_bad, tvb, offset, 1,
                                     "%s (length byte past end of options)", name);
        return;
      }
      len = tvb_get_guint8(tvb, offset + 1) << 2;  /* total including type, len */
      --length;    /* account for length byte */
      if (len < 2) {
        /* Bogus - option length is too short to include option code and
           option length. */
        proto_tree_add_expert_format(opt_tree, pinfo, ei_bad, tvb, offset, 2,
                            "%s (with too-short option length = %u byte%s)",
                            name, len, plurality(len, "", "s"));
        return;
      } else if (len - 2 > length) {
        /* Bogus - option goes past the end of the header. */
        proto_tree_add_expert_format(opt_tree, pinfo, ei_bad, tvb, offset, length,
                            "%s (option length = %u byte%s says option goes past end of options)",
                            name, len, plurality(len, "", "s"));
        return;
      } else if (len_type == OPT_LEN_FIXED_LENGTH && len != optlen) {
        /* Bogus - option length isn't what it's supposed to be for this
           option. */
        proto_tree_add_expert_format(opt_tree, pinfo, ei_bad, tvb, offset, len,
                            "%s (with option length = %u byte%s; should be %u)",
                            name, len, plurality(len, "", "s"), optlen);
        return;
      } else if (len_type == OPT_LEN_VARIABLE_LENGTH && len < optlen) {
        /* Bogus - option length is less than what it's supposed to be for
           this option. */
        proto_tree_add_expert_format(opt_tree, pinfo, ei_bad, tvb, offset, len,
                            "%s (with option length = %u byte%s; should be >= %u)",
                            name, len, plurality(len, "", "s"), optlen);
        return;
      } else {
        if (optp == NULL) {
          proto_tree_add_subtree_format(opt_tree, tvb, offset, len, ett_xstream_unknown_opt, NULL, "%s (%u byte%s)",
                              name, len, plurality(len, "", "s"));
        } else {
          if (dissect != NULL) {
            /* Option has a dissector. */
            proto_item_append_text(proto_tree_get_parent(opt_tree), ", %s",
                                   optp->name);
            (*dissect)(optp, tvb, offset, len, pinfo, opt_tree, data);
          } else {
            proto_tree *field_tree;

            /* Option has no data, hence no dissector. */
            proto_item_append_text(proto_tree_get_parent(opt_tree), ", %s",
                                   name);
            field_tree = proto_tree_add_subtree(opt_tree, tvb, offset, len, ett_xstream_option_other, NULL, name);
            dissect_ipopt_type(tvb, offset, field_tree, opttypes);
          }
        }
        len -= 2;   /* subtract size of type and length */
        offset += 2 + len;
      }
      length -= len;
    } else {
      if (dissect != NULL) {
        proto_item_append_text(proto_tree_get_parent(opt_tree), ", %s",
                               optp->name);
        (*dissect)(optp, tvb, offset, 1, pinfo, opt_tree, data);
      } else {
        proto_tree *field_tree;

        /* Option has no data, hence no dissector. */
        proto_item_append_text(proto_tree_get_parent(opt_tree), ", %s", name);
        field_tree = proto_tree_add_subtree(opt_tree, tvb, offset, 1, ett_xstream_option_other, NULL, name);
        dissect_ipopt_type(tvb, offset, field_tree, opttypes);
      }
      offset += 1;

      if (nop_count == 4 && strcmp (name, "No-Operation (NOP)") == 0) {
        expert_add_info(pinfo, opt_item, &ei_ip_nop);
      }
    }
    if (opt == eol)
      break;
  }
}

static int
dissect_xstream(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti, *tf;
    proto_item *options_item;
    proto_tree *options_tree;
    proto_tree *xstream_tree, *field_tree = NULL;
    const char *flags_str, *flags_str_first_letter;
    tvbuff_t *next_tvb;

    guint16 off = tvb_get_guint8(tvb, XSTREAM_OFF) << 2;
    guint32 seq = tvb_get_ntohl(tvb, XSTREAM_SEQNO);
    guint32 ack = tvb_get_ntohl(tvb, XSTREAM_ACKNO);
    guint32 win = tvb_get_ntohl(tvb, XSTREAM_WIN);
    guint16 flags = tvb_get_ntohs(tvb, XSTREAM_FLAGS);
    guint16 optlen = off - XSTREAM_OPTS;

    flags_str = xstream_flags_to_str(flags);
    flags_str_first_letter = xstream_flags_to_str_first_letter(flags);

    if (tvb_reported_length(tvb) < XSTREAM_MIN_LENGTH) {
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Xstream");
    col_set_str(pinfo->cinfo, COL_INFO, "XIA XStream Packet");

    ti = proto_tree_add_item(tree, proto_xstream, tvb, 0, off, ENC_NA);
    xstream_tree = proto_item_add_subtree(ti, ett_xstream);

    proto_tree_add_item(xstream_tree, hf_xstream_next_hdr, tvb, XSTREAM_NXTH, 1, ENC_BIG_ENDIAN);
	proto_tree_add_uint_format_value(xstream_tree, hf_xstream_off, tvb, XSTREAM_OFF, 1, off, "%u bytes (%u)", off, off >> 2);
    tf = proto_tree_add_uint_format(xstream_tree, hf_xstream_flags, tvb, XSTREAM_FLAGS, 2,
                                    flags, "Flags: 0x%04x (%s)", flags, flags_str);
    field_tree = proto_item_add_subtree(tf, ett_xstream_flags);
	proto_tree_add_boolean(field_tree, hf_xstream_flags_res7, tvb, XSTREAM_FLAGS, 1, flags);
	proto_tree_add_boolean(field_tree, hf_xstream_flags_res6, tvb, XSTREAM_FLAGS, 1, flags);
	proto_tree_add_boolean(field_tree, hf_xstream_flags_res5, tvb, XSTREAM_FLAGS, 1, flags);
	proto_tree_add_boolean(field_tree, hf_xstream_flags_res4, tvb, XSTREAM_FLAGS, 1, flags);
	proto_tree_add_boolean(field_tree, hf_xstream_flags_res3, tvb, XSTREAM_FLAGS, 1, flags);
	proto_tree_add_boolean(field_tree, hf_xstream_flags_res2, tvb, XSTREAM_FLAGS, 1, flags);
    proto_tree_add_boolean(field_tree, hf_xstream_flags_res1, tvb, XSTREAM_FLAGS, 1, flags);
    proto_tree_add_boolean(field_tree, hf_xstream_flags_ns, tvb, XSTREAM_FLAGS, 1, flags);
    proto_tree_add_boolean(field_tree, hf_xstream_flags_cwr, tvb, XSTREAM_FLAGS, 1, flags);
    proto_tree_add_boolean(field_tree, hf_xstream_flags_ecn, tvb, XSTREAM_FLAGS, 1, flags);
    proto_tree_add_boolean(field_tree, hf_xstream_flags_unused, tvb, XSTREAM_FLAGS, 1, flags);
    proto_tree_add_boolean(field_tree, hf_xstream_flags_ack, tvb, XSTREAM_FLAGS, 1, flags);
    proto_tree_add_boolean(field_tree, hf_xstream_flags_push, tvb, XSTREAM_FLAGS, 1, flags);
    proto_tree_add_boolean(field_tree, hf_xstream_flags_reset, tvb, XSTREAM_FLAGS, 1, flags);
    proto_tree_add_boolean(field_tree, hf_xstream_flags_syn, tvb, XSTREAM_FLAGS, 1, flags);
    proto_tree_add_boolean(field_tree, hf_xstream_flags_fin, tvb, XSTREAM_FLAGS, 1, flags);

    tf = proto_tree_add_string(field_tree, hf_xstream_flags_str, tvb, XSTREAM_FLAGS, 2, flags_str_first_letter);
    PROTO_ITEM_SET_GENERATED(tf);

    proto_tree_add_uint(xstream_tree, hf_xstream_seqno, tvb, XSTREAM_SEQNO, 4, seq);
    proto_tree_add_uint(xstream_tree, hf_xstream_ackno, tvb, XSTREAM_ACKNO, 4, ack);
    proto_tree_add_uint(xstream_tree, hf_xstream_win, tvb, XSTREAM_WIN, 4, win);

    options_item = NULL;
    options_tree = NULL;
    if (optlen) {
        guint bc = (guint)tvb_captured_length_remaining(tvb, XSTREAM_MIN_LENGTH);

        options_item = proto_tree_add_item(xstream_tree, hf_xstream_options, tvb, XSTREAM_MIN_LENGTH, (bc < optlen ? bc : optlen), ENC_NA);
        proto_item_set_text(options_item, "Options: (%u bytes)", optlen);
        options_tree = proto_item_add_subtree(options_item, ett_xstream_options);
   }

    /* Now dissect the options. */
    if (optlen) {
        dissect_xstream_options(tvb, XSTREAM_MIN_LENGTH, optlen, xstreamopts, N_XSTREAM_OPTS,
                               XSTREAM_OPT_EOL, &XSTREAM_OPT_TYPES,
                               &ei_xstream_opt_len_invalid, pinfo, options_tree,
                               options_item, NULL);
   }


    /* everything else is data */
    next_tvb = tvb_new_subset_remaining(tvb, off);
    call_data_dissector(next_tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}

void
proto_register_xstream(void)
{
    expert_module_t *expert_xstream;

    static hf_register_info hf[] = {
        {&hf_xstream_next_hdr, {"Next Header", "xstream.next_hdr",
            FT_UINT8, BASE_HEX, next_header_vals, 0x0, NULL, HFILL}},

        {&hf_xstream_off, {"Header Length", "xstream.off",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_xstream_flags, {"Flags", "xstream.flags",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{&hf_xstream_flags_res7, {"Reserved", "xstream.flags.res7",
        	FT_BOOLEAN, 16, TFS(&tfs_set_notset), TH_RES7, "Three reserved bits (must be zero)", HFILL}},

		{&hf_xstream_flags_res6, {"Reserved", "xstream.flags.res6",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), TH_RES6, "Three reserved bits (must be zero)", HFILL}},

		{&hf_xstream_flags_res5, {"Reserved", "xstream.flags.res5",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), TH_RES5, "Three reserved bits (must be zero)", HFILL}},

		{&hf_xstream_flags_res4, {"Reserved", "xstream.flags.res4",
        	FT_BOOLEAN, 16, TFS(&tfs_set_notset), TH_RES4, "Three reserved bits (must be zero)", HFILL}},

		{&hf_xstream_flags_res3, {"Reserved", "xstream.flags.res3",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), TH_RES3, "Three reserved bits (must be zero)", HFILL}},

		{&hf_xstream_flags_res2, {"Reserved", "xstream.flags.res2",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), TH_RES2, "Three reserved bits (must be zero)", HFILL}},

        {&hf_xstream_flags_res1, {"Reserved", "xstream.flags.res1",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), TH_RES1, "Three reserved bits (must be zero)", HFILL}},

        {&hf_xstream_flags_ns, {"Nonce", "xstream.flags.ns",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), TH_NS, "ECN concealment protection (RFC 3540)", HFILL}},

        {&hf_xstream_flags_cwr, {"Congestion Window Reduced (CWR)", "xstream.flags.cwr",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), TH_CWR, NULL, HFILL}},

        {&hf_xstream_flags_ecn, {"EC Echo", "xstream.flags.ece",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), TH_ECE, NULL, HFILL}},

        {&hf_xstream_flags_unused, {"Unused", "xstream.flags.unused",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), TH_UNUSED, NULL, HFILL}},

        {&hf_xstream_flags_ack, {"Acknowledgment", "xstream.flags.ack",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), TH_ACK, NULL, HFILL}},

        {&hf_xstream_flags_push, {"Push", "xstream.flags.push",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), TH_PUSH, NULL, HFILL}},

        {&hf_xstream_flags_reset, {"Reset", "xstream.flags.reset",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), TH_RST, NULL, HFILL}},

        {&hf_xstream_flags_syn, {"Syn", "xstream.flags.syn",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), TH_SYN, NULL, HFILL}},

        {&hf_xstream_flags_fin, {"Fin", "xstream.flags.fin",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), TH_FIN, NULL, HFILL}},

        {&hf_xstream_flags_str, {"XStream Flags", "xstream.flags.str",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL}},

        {&hf_xstream_seqno, {"Sequence #", "xstream.seq_no",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_xstream_ackno, {"Ack #", "xstream.ack_no",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_xstream_win, {"Window", "xstream.win", FT_UINT32,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_xstream_option_kind, {"Kind", "xstream.option_kind",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &xstream_option_kind_vs_ext, 0x0, "This XSTREAM option's kind", HFILL}},

        {&hf_xstream_option_len, {"Length", "xstream.option_len",
            FT_UINT8, BASE_DEC, NULL, 0x0, "Length of this XSTREAM option in bytes (including kind and length fields)", HFILL}},

        {&hf_xstream_options, {"Options", "xstream.options",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_xstream_option_type, {"Type", "xstream.options.type",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_xstream_option_type_copy, {"Copy on fragmentation", "xstream.options.type.copy",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), IPOPT_COPY_MASK, NULL, HFILL}},

        {&hf_xstream_option_type_class, {"Class", "xstream.options.type.class",
            FT_UINT8, BASE_DEC, VALS(ipopt_type_class_vals), IPOPT_CLASS_MASK, NULL, HFILL}},

        {&hf_xstream_option_type_number, {"Number", "xstream.options.type.number",
            FT_UINT8, BASE_DEC, VALS(ipopt_type_number_vals), IPOPT_NUMBER_MASK, NULL, HFILL}},

        {&hf_xstream_option_mss, {"XStream MSS Option", "xstream.options.mss",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_xstream_option_mss_val, {"MSS Value", "xstream.options.mss_val",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_xstream_option_wscale_shift, {"Shift count", "xstream.options.wscale.shift",
            FT_UINT8, BASE_DEC, NULL, 0x0, "Logarithmically encoded power of 2 scale factor", HFILL}},

        {&hf_xstream_option_wscale_multiplier, {"Multiplier", "xstream.options.wscale.multiplier",
            FT_UINT16, BASE_DEC, NULL, 0x0, "Multiply segment window size by this for scaled window size", HFILL}},

        {&hf_xstream_option_timestamp_tsval, {"Timestamp value", "xstream.options.timestamp.tsval",
            FT_UINT32, BASE_DEC, NULL, 0x0, "Value of sending machine's timestamp clock", HFILL}},

        {&hf_xstream_option_timestamp_tsecr, {"Timestamp echo reply", "xstream.options.timestamp.tsecr",
            FT_UINT32, BASE_DEC, NULL, 0x0, "Echoed timestamp from remote machine", HFILL}},

		{&hf_xstream_option_padding, {"Padding", "xstream.options.padding",
            FT_NONE, BASE_NONE, NULL, 0x0, "Padding byte(s)", HFILL}},

		{&hf_xstream_option_migrate, {"Migration Signature", "xstream.options.migrate",
			FT_UINT32, BASE_DEC, NULL, 0x0, "Migration Header", HFILL}},

			// FIXME: these need to change to handle binary eventually instead of strings
		{&hf_xstream_option_migrate_len, {"Length", "xstream.options.migrate.len",
			FT_UINT8, BASE_DEC, NULL, 0x0, "Length of this migrate option item (including count and length fields)", HFILL}},

		{&hf_xstream_option_migrate_count, {"Num Items", "xstream.options.migrate.len",
			FT_UINT8, BASE_DEC, NULL, 0x0, "Number of subitems in this migrate option", HFILL}},

		{&hf_xstream_option_migrate_src, {"Source DAG", "xstream.options.src.dag",
			FT_STRING, STR_ASCII, NULL, 0x0, "Source DAG", HFILL}},

		{&hf_xstream_option_migrate_dst, {"Destination DAG", "xstream.options.src.dag",
			FT_STRING, STR_ASCII, NULL, 0x0, "Destination DAG", HFILL}},

		{&hf_xstream_option_migrate_ts, {"Timestamp", "xstream.options.timestamp",
			FT_STRING, STR_ASCII, NULL, 0x0, "Migration timestamp", HFILL}},

		{&hf_xstream_option_migrate_signature, {"Signature", "xstream.options.signature",
			FT_BYTES, ENC_NA, NULL, 0x0, "Migration option's signature", HFILL}},

		{&hf_xstream_option_migrate_key, {"Public Key", "xstream.options.key",
			FT_STRING, ENC_NA, NULL, 0x0, "Sending host's public key", HFILL}},

		{&hf_xstream_option_migrate_ack, {"Migration ACK Signature", "xstream.options.migrate.ack",
			FT_UINT32, BASE_DEC, NULL, 0x0, "Migration ACK Header", HFILL}}
    };

    static gint *ett[] = {
        &ett_xstream,
        &ett_xstream_flags,
        &ett_xstream_options,
        &ett_xstream_option_type,
        &ett_xstream_option_wscale,
        &ett_xstream_option_timestamp,
        &ett_xstream_option_mss,
		&ett_xstream_option_migrate,
		&ett_xstream_option_migrate_payload,
		&ett_xstream_option_migrate_sig,
		&ett_xstream_option_migrate_key,
		&ett_xstream_option_migrate_ack,
		&ett_xstream_unknown_opt,
		&ett_xstream_option_other

    };

    static ei_register_info ei[] = {
        {&ei_xstream_opt_len_invalid, {"xstream.option.len.invalid", PI_SEQUENCE, PI_NOTE, "Invalid length for option", EXPFILL}},
        {&ei_xstream_option_wscale_shift_invalid, {"xstream.options.wscale.shift.invalid", PI_PROTOCOL, PI_WARN, "Window scale shift exceeds 14", EXPFILL}},
        {&ei_xstream_short_segment, {"xstream.short_segment", PI_MALFORMED, PI_WARN, "Short segment", EXPFILL}},
        {&ei_xstream_ack_nonzero, {"xstream.ack.nonzero", PI_PROTOCOL, PI_NOTE, "The acknowledgment number field is nonzero while the ACK flag is not set", EXPFILL}},
        {&ei_xstream_suboption_malformed, {"xstream.suboption_malformed", PI_MALFORMED, PI_ERROR, "suboption would go past end of option", EXPFILL}},
        {&ei_xstream_next_header, {"xstream.next.header", PI_MALFORMED, PI_WARN, "Unknown next header", EXPFILL}},
        {&ei_xstream_invalid_len, {"xstream.invalid.len", PI_MALFORMED, PI_ERROR, "Invalid length", EXPFILL}},
		{ &ei_ip_nop, { "ip.nop", PI_PROTOCOL, PI_WARN, "4 NOP in a row - a router may have removed some options", EXPFILL }},
  };

    proto_xstream = proto_register_protocol("XIA XStream", "XStream", "xstream");

    proto_register_field_array(proto_xstream, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    xstream_handle = register_dissector("xstream", dissect_xstream, proto_xstream);

    expert_xstream = expert_register_protocol(proto_xstream);
    expert_register_field_array(expert_xstream, ei, array_length(ei));
}

void
proto_reg_handoff_xstream(void)
{
    xstream_handle = create_dissector_handle(dissect_xstream, proto_xstream);
    dissector_add_uint("xip.next_hdr", XIA_NEXT_HEADER_XSTREAM, xstream_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
