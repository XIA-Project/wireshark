/* packet-xia-xarp.c
 * Routines for XIA Address Resolution Protocol (XARP) packet disassembly
 * Copyright 2016 Dan Barrett <barrettd@cs.cmu.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * By Deepti Ragha <dlragha@ncsu.edu>
 * Copyright 2012 Deepti Ragha
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
/*
 * More information about XIA can be found here:
 *  https://www.cs.cmu.edu/~xia/
 *  https://github.com/XIAProject/xia-core
 *  https://github.com/AltraMayor/XIA-for-Linux/wiki
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <epan/arptypes.h>
#include <epan/addr_resolv.h>
#include <epan/expert.h>
#include "packet-xip.h"

void proto_register_xarp(void);
void proto_reg_handoff_xarp(void);

static int proto_xarp = -1;
static int hf_xarp_hard_type = -1;
static int hf_xarp_proto_type = -1;
static int hf_xarp_hard_size = -1;
static int hf_xarp_proto_size = -1;
static int hf_xarp_opcode = -1;
static int hf_xarp_src_hw_mac = -1;
static int hf_xarp_src_xip = -1;
static int hf_xarp_dst_hw_mac = -1;
static int hf_xarp_dst_xip = -1;

static gint ett_xarp = -1;

static expert_field ei_xarp_invalid_len = EI_INIT;

static dissector_handle_t xarp_handle;

/*  Offsets of fields within an XARP packet */
#define AR_HRD 0
#define AR_PRO 2
#define AR_HLN 4
#define AR_PLN 5
#define AR_OP  6
#define MIN_XARP_HEADER_SIZE 8

/* XIA only supports 2 ARP operations */
#define XARPOP_REQUEST 1
#define XARPOP_REPLY   2

static const value_string op_vals[] = {
    {XARPOP_REQUEST, "request"},
    {XARPOP_REPLY,   "reply"  },
    {0, NULL}};

static const value_string etype_vals[] = {
    {ETHERTYPE_XIP,   "XIP"  },
    {ETHERTYPE_XARP,  "XARP" },
    {ETHERTYPE_XNETJ, "XNETJ"},
    {0, NULL}
};

static const value_string hw_vals[] = {
    {ARPHRD_ETHER, "Ethernet"},
    {0, NULL}
};


// FIXME: move to common code location
static const gchar *
xid_to_str(tvbuff_t *tvb, gint offset, int condense)
{
    gint32 type;
    wmem_strbuf_t *buf;

    type = tvb_get_ntohl(tvb, offset);
    buf = wmem_strbuf_sized_new(wmem_packet_scope(), 64, 64);
	offset += sizeof(gint32);

	if (condense) {
		wmem_strbuf_append_printf(buf, "%s:%04x...%04x",
	        try_val_to_str(type, xidtype_vals),
	        tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN),
	        tvb_get_guint16(tvb, offset + 9 * sizeof(gint16), ENC_BIG_ENDIAN));
	} else {
	    wmem_strbuf_append_printf(buf, "%s:%08x%08x%08x%08x%08x",
	        try_val_to_str(type, xidtype_vals),
	        tvb_get_guint32(tvb, offset + 0 * sizeof(gint32), ENC_BIG_ENDIAN),
	        tvb_get_guint32(tvb, offset + 1 * sizeof(gint32), ENC_BIG_ENDIAN),
	        tvb_get_guint32(tvb, offset + 2 * sizeof(gint32), ENC_BIG_ENDIAN),
	        tvb_get_guint32(tvb, offset + 3 * sizeof(gint32), ENC_BIG_ENDIAN),
	        tvb_get_guint32(tvb, offset + 4 * sizeof(gint32), ENC_BIG_ENDIAN));
	}

    return wmem_strbuf_get_str(buf);
}

gboolean
capture_xarp(const guchar *pd _U_, int offset _U_, int len _U_, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header _U_)
{
    capture_dissector_increment_count(cpinfo, proto_xarp);
    return TRUE;
}

static int
dissect_xarp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    guint16 ar_hrd;
    guint16 ar_pro;
    guint8  ar_hln;
    guint8  ar_pln;
    guint16 ar_op;
    guint32 needed_len;
    guint32 actual_len;
    guint32 sha_offset, spa_offset, tha_offset, tpa_offset;
    proto_item *ti;
    proto_tree *xarp_tree = NULL;
    const gchar *src_xid_str = NULL;
    const gchar *tgt_xid_str = NULL;

    /* make sure we have enough data for a simple XARP header */
    actual_len = tvb_reported_length(tvb);
    if (actual_len < MIN_XARP_HEADER_SIZE) {
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "XARP");

    ar_hrd = tvb_get_ntohs(tvb, AR_HRD);
    ar_pro = tvb_get_ntohs(tvb, AR_PRO);
    ar_hln = tvb_get_guint8(tvb, AR_HLN);
    ar_pln = tvb_get_guint8(tvb, AR_PLN);
    ar_op  = tvb_get_ntohs(tvb, AR_OP);

    needed_len = MIN_XARP_HEADER_SIZE + ar_hln * 2 + ar_pln * 2;

    sha_offset = MIN_XARP_HEADER_SIZE;
    spa_offset = sha_offset + ar_hln;
    tha_offset = spa_offset + ar_pln;
    tpa_offset = tha_offset + ar_hln;

    ti = proto_tree_add_protocol_format(tree, proto_xarp, tvb, 0, needed_len, "XIA Address Resolution Protocol");
    xarp_tree = proto_item_add_subtree(ti, ett_xarp);
    proto_tree_add_uint(xarp_tree, hf_xarp_hard_type, tvb, AR_HRD, 2, ar_hrd);
    proto_tree_add_uint(xarp_tree, hf_xarp_proto_type, tvb, AR_PRO, 2, ar_pro);
    proto_tree_add_uint(xarp_tree, hf_xarp_hard_size, tvb, AR_HLN, 1, ar_hln);
    proto_tree_add_uint(xarp_tree, hf_xarp_proto_size, tvb, AR_PLN, 1, ar_pln);
    proto_tree_add_uint(xarp_tree, hf_xarp_opcode, tvb, AR_OP,  2, ar_op);

    if (needed_len <= actual_len) {
        src_xid_str = xid_to_str(tvb, spa_offset, FALSE);
        tgt_xid_str = xid_to_str(tvb, tpa_offset, FALSE);

        proto_tree_add_item(xarp_tree, hf_xarp_src_hw_mac,tvb, sha_offset, ar_hln, ENC_BIG_ENDIAN);
        proto_tree_add_string_format(xarp_tree, hf_xarp_src_xip, tvb, spa_offset, 24, src_xid_str, "Source XID: %s", src_xid_str);
        proto_tree_add_item(xarp_tree, hf_xarp_dst_hw_mac, tvb, tha_offset, ar_hln, ENC_BIG_ENDIAN);
        proto_tree_add_string_format(xarp_tree, hf_xarp_dst_xip, tvb, tpa_offset, 24, tgt_xid_str, "Target XID: %s", tgt_xid_str);

		src_xid_str = xid_to_str(tvb, spa_offset, TRUE);
        tgt_xid_str = xid_to_str(tvb, tpa_offset, TRUE);

        switch (ar_op) {
        case XARPOP_REQUEST:
            col_add_fstr(pinfo->cinfo, COL_INFO, "Who has %s? Tell %s", tgt_xid_str, src_xid_str);
            break;
        case XARPOP_REPLY:
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s is at %s", src_xid_str, tvb_ether_to_str(tvb, sha_offset));
            break;
        default:
            col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown XARP opcode 0x%04x", ar_op);
            break;
        }

    } else {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Truncated Packet!");
        expert_add_info_format(pinfo, ti, &ei_xarp_invalid_len,
            "Packet size is too small: received %d bytes, need %d",
            actual_len, needed_len);
            return MIN_XARP_HEADER_SIZE;
    }

    return tvb_captured_length(tvb);
}

void
proto_register_xarp(void)
{
    static hf_register_info hf[] = {
        { &hf_xarp_hard_type,  {"Hardware type", "xarp.hw.type",         FT_UINT16, BASE_HEX,  VALS(hw_vals), 0x0, NULL, HFILL}},
        { &hf_xarp_proto_type, {"Protocol type", "xarp.proto.type",      FT_UINT16, BASE_HEX,  VALS(etype_vals), 0x0, NULL, HFILL}},
        { &hf_xarp_hard_size,  {"Hardware size", "xarp.hw.size",         FT_UINT8,  BASE_DEC,  NULL, 0x0, NULL, HFILL}},
        { &hf_xarp_proto_size, {"Protocol size", "xarp.proto.size",      FT_UINT8,  BASE_DEC,  NULL, 0x0, NULL, HFILL}},
        { &hf_xarp_opcode,     {"Opcode", "xarp.opcode",                 FT_UINT16, BASE_DEC,  VALS(op_vals), 0x0, NULL, HFILL}},
        { &hf_xarp_src_hw_mac, {"Sender MAC address", "xarp.src.hw_mac", FT_ETHER,  BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_xarp_src_xip,    {"Sender XID", "xarp.src.xip",            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_xarp_dst_hw_mac, {"Target MAC address", "xarp.dst.hw_mac", FT_ETHER,  BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_xarp_dst_xip,    {"Target XID", "xarp.dst.xip",            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    };

    static ei_register_info ei[] = {{ &ei_xarp_invalid_len, {"xarp.invalid.len", PI_MALFORMED, PI_ERROR, "Invalid length", EXPFILL}},
    };

    expert_module_t* expert_xarp;

    static gint *ett[] = {
        &ett_xarp,
    };

    proto_xarp = proto_register_protocol("XIA Address Resolution Protocol", "XARP", "xarp");

    proto_register_field_array(proto_xarp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_xarp = expert_register_protocol(proto_xarp);
    expert_register_field_array(expert_xarp, ei, array_length(ei));

    xarp_handle = register_dissector( "xarp" , dissect_xarp, proto_xarp );
}

void
proto_reg_handoff_xarp(void)
{
    dissector_add_uint("ethertype", ETHERTYPE_XARP, xarp_handle);
    register_capture_dissector("ethertype", ETHERTYPE_XARP, capture_xarp, proto_xarp);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=8:tabSize=8:noTabs=true:
 */
