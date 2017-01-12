/* packet-xip-fid.c
 * Routines for XDatagram dissection
 * Copyright 2016, Dan Barrett <barrettd@cs.cmu.edu>
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
 *
 * More information about the format of the DAG can be found here:
 *  https://github.com/AltraMayor/XIA-for-Linux/wiki/Human-readable-XIP-address-format
 */
#include <config.h>
#include <epan/packet.h>
#include "packet-xip.h"

void proto_reg_handoff_fid(void);
void proto_register_fid(void);

static int proto_fid = -1;
static int hf_fid_next_hdr = -1;
static int hf_fid_hlen = -1;
static int hf_fid_extra = -1;
static int hf_fid_seq = -1;
static int hf_fid_time = -1;

static dissector_handle_t fid_handle;
static dissector_handle_t fid_xdgram_handle;
static dissector_handle_t fid_xstream_handle;
static dissector_handle_t fid_xcmp_handle;

static gint ett_fid = -1;

#define MIN_FID_HEADER_SIZE 12

// offsets in bytes
#define FID_NXTH  0
#define FID_HLEN  1
#define FID_EXTRA 2
#define FID_SEQ   4
#define FID_TIME  8


static gint
dissect_next_header(gint next, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	/*proto_item *next_ti,*/ gint offset)
{
	tvbuff_t *next_tvb;

	switch (next) {
	case XIA_NEXT_HEADER_XDGRAM:
		next_tvb = tvb_new_subset_remaining(tvb, offset);
		return call_dissector(fid_xdgram_handle, next_tvb, pinfo, tree);

	case XIA_NEXT_HEADER_FID:
		next_tvb = tvb_new_subset_remaining(tvb, offset);
		return call_dissector(fid_handle, next_tvb, pinfo, tree);

	case XIA_NEXT_HEADER_XSTREAM:
		next_tvb = tvb_new_subset_remaining(tvb, offset);
		return call_dissector(fid_xstream_handle, next_tvb, pinfo, tree);

	case XIA_NEXT_HEADER_XCMP:
		next_tvb = tvb_new_subset_remaining(tvb, offset);
		return call_dissector(fid_xcmp_handle, next_tvb, pinfo, tree);

	case XIA_NEXT_HEADER_DATA:
		next_tvb = tvb_new_subset_remaining(tvb, offset);
		return call_data_dissector(next_tvb, pinfo, tree);
	default:
		//expert_add_info_format(pinfo, next_ti, &ei_xip_next_header,
		// "Unrecognized next header: 0x%02x", next_header);
		return 0;
	}
}



static int
dissect_fid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint8 hlen;
	guint8 next;
    proto_item *ti;
    guint32 actual_len;
	//tvbuff_t *next_tvb;
    proto_tree *fid_tree;
	//proto_item *next_ti = NULL;

	gint offset = MIN_FID_HEADER_SIZE;

    /* make sure we have enough data for a simple FID header */
    actual_len = tvb_reported_length(tvb);
    if (actual_len < MIN_FID_HEADER_SIZE) {
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FID");
    col_set_str(pinfo->cinfo, COL_INFO, "XIA FID Header");

	/* header length is right shited by 2 on the wire */
    hlen = tvb_get_guint8(tvb, FID_HLEN) << 2;
	next = tvb_get_guint8(tvb, FID_NXTH);

    ti = proto_tree_add_protocol_format(tree, proto_fid, tvb, 0, hlen, "XIA FID Header");
    fid_tree = proto_item_add_subtree(ti, ett_fid);

    proto_tree_add_item(fid_tree, hf_fid_next_hdr, tvb, FID_NXTH, 1, ENC_BIG_ENDIAN);
    proto_tree_add_uint(fid_tree, hf_fid_hlen, tvb, FID_HLEN, 1, hlen);
    proto_tree_add_item(fid_tree, hf_fid_extra, tvb, FID_EXTRA, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(fid_tree, hf_fid_seq, tvb, FID_SEQ, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(fid_tree, hf_fid_time, tvb, FID_TIME, 4, ENC_BIG_ENDIAN);

	/* Add next header. */
	//next_ti = proto_tree_add_item(fid_tree, hf_fid_next_hdr, tvb,
	//	FID_NXTH, 1, ENC_BIG_ENDIAN);


	return dissect_next_header(next, tvb, pinfo, tree, /*next_ti,*/ offset);

//    next_tvb = tvb_new_subset_remaining(tvb, hlen);
//    call_data_dissector(next_tvb, pinfo, tree);
//    return tvb_captured_length(tvb);
}

void
proto_register_fid(void)
{
    static hf_register_info hf[] = {
		{&hf_fid_next_hdr, {"Next Header", "fid.next_hdr", FT_UINT8,
			BASE_HEX, next_header_vals, 0x0, NULL, HFILL}},

		{&hf_fid_hlen, {"Header Length", "fid.hlen", FT_UINT8,
		BASE_DEC, NULL, 0x0, NULL, HFILL}},

		{&hf_fid_extra, {"Extra Bytes", "fid.extra", FT_UINT16,
			BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{&hf_fid_seq, {"Sequence Number", "fid.seq", FT_UINT32,
			BASE_DEC, NULL, 0x0, NULL, HFILL}},

		{&hf_fid_time, {"Timestamp", "fid.timestamp", FT_UINT32,
			BASE_DEC, NULL, 0x0, NULL, HFILL}}
    };

    static gint *ett[] = {
        &ett_fid
    };

    proto_fid = proto_register_protocol("XIA FID", "FID", "fid");
    proto_register_field_array(proto_fid, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    fid_handle = register_dissector("fid", dissect_fid, proto_fid);
}

void
proto_reg_handoff_fid(void)
{
    fid_handle = create_dissector_handle(dissect_fid, proto_fid);

	fid_xcmp_handle = find_dissector_add_dependency("xcmp", proto_fid);
	fid_xstream_handle = find_dissector_add_dependency("xstream", proto_fid);
	fid_xdgram_handle = find_dissector_add_dependency("xdatagram", proto_fid);
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
