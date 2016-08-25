/* packet-xip-xdgram.c
 * Routines for XDatagram dissection
 * Copyright 2016, Carnegie Mellon University
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
 *
 * And here:
 *  https://github.com/XIAProject/xia-core
 *
 * And here:
 *  https://github.com/AltraMayor/XIA-for-Linux/wiki
 *
 * More information about the format of the DAG can be found here:
 *  https://github.com/AltraMayor/XIA-for-Linux/wiki/Human-readable-XIP-address-format
 */

#include <config.h>
#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */
//#include <epan/expert.h>   /* Include only as needed */

void proto_reg_handoff_xdgram(void);
void proto_register_xdgram(void);

static int proto_xdgram = -1;
static int hf_xdgram_next_hdr = -1;
static int hf_xdgram_hlen = -1;
static int hf_xdgram_extra = -1;

static dissector_handle_t xdgram_handle;

//static expert_field ei_xdgram_invalid_len = EI_INIT;
//static expert_field ei_xdgram_next_header = EI_INIT;

static gint ett_xdgram = -1;

#define XDGRAM_MIN_LENGTH 4

// offsets in bytes
#define XDGRAM_NXTH		0
#define XDGRAM_HLEN		1
#define XDGRAM_EXTRA	2

#define XIA_NEXT_HEADER_DATA	0
#define XIA_NEXT_HEADER_XCMP	0x01
#define XIA_NEXT_HEADER_XDGRAM	0x02
#define XIA_NEXT_HEADER_XSTREAM	0x03

/* Principal string values. */
static const value_string next_header_vals[] = {
	{ XIA_NEXT_HEADER_DATA,	  "Data" },
	{ XIA_NEXT_HEADER_XCMP,	  "XCMP" },
	{ XIA_NEXT_HEADER_XDGRAM, "Xdatagram" },
	{ XIA_NEXT_HEADER_XSTREAM,"Xstream" },
	{ 0,			NULL }
};

static int
dissect_xdgram(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
	//proto_item *expert_ti;
    proto_tree *xdgram_tree;
	tvbuff_t *next_tvb;

	//proto_item *next_ti = NULL;
	//proto_item *hlen_ti = NULL;

	guint8 hlen = tvb_get_guint8(tvb, XDGRAM_HLEN) << 2;

    if (tvb_reported_length(tvb) < XDGRAM_MIN_LENGTH)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Xdgram");
    col_set_str(pinfo->cinfo, COL_INFO, "XIA XDatagram Packet");

    ti = proto_tree_add_item(tree, proto_xdgram, tvb, 0, hlen, ENC_NA);

    xdgram_tree = proto_item_add_subtree(ti, ett_xdgram);

	//next_ti = proto_tree_add_item(xdgram_tree, hf_xdgram_next_hdr, tvb,
	proto_tree_add_item(xdgram_tree, hf_xdgram_next_hdr, tvb,
		XDGRAM_NXTH, 1, ENC_BIG_ENDIAN);

	//hlen_ti = proto_tree_add_item(xdgram_tree, hf_xdgram_hlen, tvb,
	proto_tree_add_item(xdgram_tree, hf_xdgram_hlen, tvb,
		XDGRAM_HLEN, 1, ENC_BIG_ENDIAN);

	proto_tree_add_item(xdgram_tree, hf_xdgram_extra, tvb,
		XDGRAM_EXTRA, 2, ENC_BIG_ENDIAN);

	// everything else is data
	next_tvb = tvb_new_subset_remaining(tvb, hlen);
	call_data_dissector(next_tvb, pinfo, tree);

    /* Some fields or situations may require "expert" analysis that can be
     * specifically highlighted. */
//    if ( TEST_EXPERT_condition )
//        /* value of hf_xdgram_FIELDABBREV isn't what's expected */
//        expert_add_info(pinfo, expert_ti, &ei_xdgram_EXPERTABBREV);

    return tvb_captured_length(tvb);
}

void
proto_register_xdgram(void)
{
//    expert_module_t *expert_xdgram;

    static hf_register_info hf[] = {
		{ &hf_xdgram_next_hdr,
		{ "Next Header", "xdgram.next_hdr", FT_UINT8,
		   BASE_HEX, next_header_vals, 0x0, NULL, HFILL }},

		{ &hf_xdgram_hlen,
		{ "Header Length (in dwords)", "xdgram.hlen", FT_UINT8,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

   		{ &hf_xdgram_extra,
   		{ "Extra Bytes (unused)", "xdgram.extra", FT_UINT16,
   		   BASE_HEX, NULL, 0x0,	NULL, HFILL }}
    };

    static gint *ett[] = {
        &ett_xdgram
    };

//    static ei_register_info ei[] = {
//		{ &ei_xdgram_next_header,
//		{ "xdgram.next.header", PI_MALFORMED, PI_WARNING,
//		  "Unknown next header", EXPFILL }},
//
//		{ &ei_xdgram_invalid_len,
//		{ "xdgram.invalid.len", PI_MALFORMED, PI_ERROR,
//		  "Invalid length", EXPFILL }},
//    };

    proto_xdgram = proto_register_protocol("XIA XDatagram", "XDgram", "xdgram");

    proto_register_field_array(proto_xdgram, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

	xdgram_handle = register_dissector("xdatagram", dissect_xdgram,
		proto_xdgram);

//    expert_xdgram = expert_register_protocol(proto_xdgram);
//    expert_register_field_array(expert_xdgram, ei, array_length(ei));
}

void
proto_reg_handoff_xdgram(void)
{
	xdgram_handle = create_dissector_handle(dissect_xdgram, proto_xdgram);
	dissector_add_uint("xip.next_hdr", XIA_NEXT_HEADER_XDGRAM, xdgram_handle);
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
