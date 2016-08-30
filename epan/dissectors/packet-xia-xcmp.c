/* packet-xia-xcmp.c
 * Routines for XIA Control Message Protocol (XCMP) packet disassembly
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

static int proto_xcmp = -1;
static int hf_xcmp_type = -1;
static int hf_xcmp_code = -1;
static int hf_xcmp_seq = -1;
static int hf_xcmp_id = -1;
static int hf_xcmp_chksum = -1;
static int hf_xcmp_time = -1;
static int hf_xcmp_time_relative = -1;

static gint ett_xcmp = -1;

static dissector_handle_t xcmp_handle;

#define XIA_NEXT_HEADER_XCMP 0x01

/*  Offsets of fields within an XCMP packet */
#define XCMP_TYPE   0
#define XCMP_CODE   1
#define XCMP_CHKSUM 2

/* echo field offsets */
#define XCMP_ECHO_ID   4
#define XCMP_ECHO_SEQ  6
#define XCMP_ECHO_TIME 8

#define MIN_XCMP_HEADER_SIZE 4
#define MIN_ECHO_HEADER_SIZE 8
#define NUM_TIME_BYTES       8

/* XIA only uses a limited # of types */
#define    XCMP_ECHOREPLY 0
#define    XCMP_UNREACH   3
#define    XCMP_REDIRECT  5
#define    XCMP_ECHO      8
#define    XCMP_TIMXCEED  11

static const value_string type_vals[] = {
    { XCMP_ECHOREPLY, "Pong"        },
    { XCMP_UNREACH,   "Unreachable" },
    { XCMP_REDIRECT,  "Redirect"    },
    { XCMP_ECHO,      "Ping"        },
    { XCMP_TIMXCEED,  "TTL Exceeded"},
    {0, NULL}};

/*  FIXME: move this stuff to a common file */
/*  XIA principals */
#define XIDTYPE_NAT    0x00
#define XIDTYPE_AD     0x10
#define XIDTYPE_HID    0x11
#define XIDTYPE_CID    0x12
#define XIDTYPE_SID    0x13
#define XIDTYPE_UNI4ID 0x14
#define XIDTYPE_I4ID   0x15
#define XIDTYPE_U4ID   0x16
#define XIDTYPE_XDP    0x17
#define XIDTYPE_SRVCID 0x18
#define XIDTYPE_FLOWID 0x19
#define XIDTYPE_ZF     0x20

/*  Principal string values */
static const value_string xidtype_vals[] = {
    { XIDTYPE_AD,     "ad" },
    { XIDTYPE_HID,    "hid" },
    { XIDTYPE_CID,    "cid" },
    { XIDTYPE_SID,    "sid" },
    { XIDTYPE_UNI4ID, "uni4id" },
    { XIDTYPE_I4ID,   "i4id" },
    { XIDTYPE_U4ID,   "u4id" },
    { XIDTYPE_XDP,    "xdp" },
    { XIDTYPE_SRVCID, "serval" },
    { XIDTYPE_FLOWID, "flowid" },
    { XIDTYPE_ZF,     "zf" },
    { 0,              NULL }
};

gboolean
capture_xcmp(const guchar *pd _U_, int offset _U_, int len _U_, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header _U_)
{
    capture_dissector_increment_count(cpinfo, proto_xcmp);
    return TRUE;
}

static int
dissect_xcmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    gint8       type;
    guint16     chksum;
    guint16     seq;
    guint16     id;
    guint16     tot_len;
    guint16     actual_len;
    proto_tree *xcmp_tree = NULL;
    proto_item *ti;
    tvbuff_t   *next_tvb;
    nstime_t    ts, time_relative;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "XCMP");

    type = tvb_get_guint8(tvb, XCMP_TYPE);
    chksum = tvb_get_ntohs(tvb, XCMP_CHKSUM);

    actual_len = tvb_reported_length(tvb);
    if (type == XCMP_ECHO || type == XCMP_ECHOREPLY) {

        tot_len = MIN_ECHO_HEADER_SIZE + NUM_TIME_BYTES;
        if (tot_len > actual_len) {
            tot_len = MIN_ECHO_HEADER_SIZE;
        }
    } else {
        tot_len = MIN_XCMP_HEADER_SIZE;
    }

    if (tree) {
        ti = proto_tree_add_protocol_format(tree, proto_xcmp, tvb, 0, tot_len, "XIA Control Message Protocol");
        xcmp_tree = proto_item_add_subtree(ti, ett_xcmp);
        proto_tree_add_item(xcmp_tree, hf_xcmp_type, tvb, XCMP_TYPE, 1, ENC_NA);
        proto_tree_add_item(xcmp_tree, hf_xcmp_code, tvb, XCMP_CODE, 1, ENC_NA);
        proto_tree_add_uint(xcmp_tree, hf_xcmp_chksum, tvb, XCMP_CHKSUM, 2, chksum);
    }

    switch (type) {
    case XCMP_UNREACH:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Foo is unreachable");
        break;

    case XCMP_TIMXCEED:
        col_add_fstr(pinfo->cinfo, COL_INFO, "TTL Exceeded");
        break;

    case XCMP_ECHOREPLY:
    case XCMP_ECHO:
        seq = tvb_get_ntohs(tvb, XCMP_ECHO_SEQ);
        id = tvb_get_ntohs(tvb, XCMP_ECHO_ID);
        proto_tree_add_uint(xcmp_tree, hf_xcmp_id,  tvb, XCMP_ECHO_ID,  2, id);
        proto_tree_add_uint(xcmp_tree, hf_xcmp_seq, tvb, XCMP_ECHO_SEQ, 2, seq);

        if (tot_len >= MIN_ECHO_HEADER_SIZE + NUM_TIME_BYTES) {
            ts.secs = tvb_get_ntohl(tvb, XCMP_ECHO_TIME);
            ts.nsecs = tvb_get_ntohl(tvb, XCMP_ECHO_TIME + 4);    /* Leave at microsec resolution for now */
            if ((guint32) (ts.secs - pinfo->abs_ts.secs) >=
                3600 * 24 || ts.nsecs >= 1000000) {
                /* Timestamp does not look right in BE, try LE representation */
                ts.secs = tvb_get_letohl(tvb, 8);
                ts.nsecs = tvb_get_letohl(tvb, 8 + 4);    /* Leave at microsec resolution for now */
            }
            if ((guint32) (ts.secs - pinfo->abs_ts.secs) <
                3600 * 24 && ts.nsecs < 1000000) {
                ts.nsecs *= 1000;    /* Convert to nanosec resolution */
                proto_tree_add_time(xcmp_tree, hf_xcmp_time,
                            tvb, XCMP_ECHO_TIME, 8, &ts);
                nstime_delta(&time_relative, &pinfo->abs_ts,
                         &ts);
                ti = proto_tree_add_time(xcmp_tree,
                             hf_xcmp_time_relative,
                             tvb, 8, 8,
                             &time_relative);
                PROTO_ITEM_SET_GENERATED(ti);
           }
        }
        col_add_fstr(pinfo->cinfo, COL_INFO, (type == XCMP_ECHO) ? "Ping" : "Pong");
        col_append_fstr(pinfo->cinfo, COL_INFO, " id=0x%04x, seq=%u",
            tvb_get_ntohs(tvb, 4), tvb_get_ntohs(tvb, 6));
        break;

    default:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown XCMP type 0x%0x", type);
        break;
    }

    /* everything else is data */
    next_tvb = tvb_new_subset_remaining(tvb, tot_len);
    call_data_dissector(next_tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}

void
proto_register_xcmp(void)
{
    static hf_register_info hf[] = {
        { &hf_xcmp_type,   { "Type", "xcmp.type",       FT_UINT8,  BASE_DEC, VALS(type_vals), 0x0, NULL, HFILL }},
        { &hf_xcmp_code,   { "Code", "xcmp.code",       FT_UINT8,  BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_xcmp_chksum, { "Checksum", "xcmp.chksum", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_xcmp_id,     { "ID", "xcmp.echo.id",      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_xcmp_seq,    { "Sequence No", "xcmp.echo.seq", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        {&hf_xcmp_time,
         {"Timestamp from xcmp data", "xcmp.echo.time",
          FT_ABSOLUTE_TIME,
          ABSOLUTE_TIME_LOCAL, NULL, 0x0,
          "The timestamp in the first 8 bytes of the xcmp data",
          HFILL}},

        {&hf_xcmp_time_relative,
         {"Timestamp from xcmp data (relative)",
          "xcmp.echo.time_relative",
          FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
          "The timestamp of the packet, relative to the timestamp in the first 8 bytes of the xcmp data",
          HFILL}}
    };

    static gint *ett[] = {
        &ett_xcmp,
    };

    proto_xcmp = proto_register_protocol("XIA Control Message Protocol", "XCMP", "xcmp");

    proto_register_field_array(proto_xcmp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    xcmp_handle = register_dissector( "xcmp" , dissect_xcmp, proto_xcmp );
}

void
proto_reg_handoff_xcmp(void)
{
    xcmp_handle = create_dissector_handle(dissect_xcmp, proto_xcmp);
    dissector_add_uint("xip.next_hdr", XIA_NEXT_HEADER_XCMP, xcmp_handle);
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
