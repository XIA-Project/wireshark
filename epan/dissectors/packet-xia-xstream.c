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
 *
 * And here:
 *  https://github.com/XIAProject/xia-core
 *
 * And here:
 *  https://github.com/AltraMayor/XIA-for-Linux/wiki
 */

#include <config.h>
#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */
//#include <epan/expert.h>   /* Include only as needed */

void proto_reg_handoff_xstream(void);
void proto_register_xstream(void);

static int proto_xstream = -1;
static int hf_xstream_next_hdr = -1;
static int hf_xstream_off = -1;
static int hf_xstream_flags = -1;
static int hf_xstream_seqno = -1;
static int hf_xstream_ackno = -1;
static int hf_xstream_win = -1;
static int hf_xstream_opts = -1;

static dissector_handle_t xstream_handle;

//static expert_field ei_xstream_invalid_len = EI_INIT;
//static expert_field ei_xstream_next_header = EI_INIT;

static gint ett_xstream = -1;

#define XSTREAM_MIN_LENGTH 4

// offsets in bytes
#define XSTREAM_NXTH	0
#define XSTREAM_OFF		1
#define XSTREAM_FLAGS	2
#define XSTREAM_SEQNO	4
#define XSTREAM_ACKNO	8
#define XSTREAM_WIN		12
#define XSTREAM_OPTS	16

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

#if 0
void
XStream::_tcp_dooptions(const u_char *cp, int cnt, uint8_t th_flags,
	int * ts_present, u_long *ts_val, u_long *ts_ecr)
{
	uint16_t mss;
	int opt, optlen;
	optlen = 0;

	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		opt = cp[0];
		if (opt == TCPOPT_EOL) {
			break;
		}
		if (opt == TCPOPT_NOP)
			optlen = 1;
		else {
			if (cnt < 2){
				break;
			}
			optlen = cp[1];
			if (optlen < 1 || optlen > cnt ) {
				break;
			}
		}
		switch (opt) {
			case TCPOPT_MAXSEG:
				if (optlen != TCPOLEN_MAXSEG) {
					continue;
				}
				if (!(th_flags & XTH_SYN)) {
					continue;
				}
				memcpy((char*) &mss, (char*) cp + 2, sizeof(mss));
				mss = ntohs(mss);
				tcp_mss(mss);
				break;

			case TCPOPT_TIMESTAMP:
				if (optlen != TCPOLEN_TIMESTAMP)
					continue;
				*ts_present = 1;
				bcopy((char *)cp + 2, (char *)ts_val, sizeof(*ts_val)); //FIXME: Misaligned
				*ts_val = ntohl(*ts_val);
				bcopy((char *)cp + 6, (char *)ts_ecr, sizeof(*ts_ecr)); //FIXME: Misaligned
				*ts_ecr = ntohl(*ts_ecr);

				if (th_flags & XTH_SYN) {
					tp->t_flags |= TF_RCVD_TSTMP;
					tp->ts_recent = *ts_val;
					tp->ts_recent_age = get_transport()->tcp_now();
				}
				break;
			case TCPOPT_WSCALE:
				if (optlen != TCPOLEN_WSCALE)
					continue;
				if (!(th_flags & XTH_SYN))
					continue;
				tp->t_flags |=  TF_RCVD_SCALE;

				tp->requested_s_scale = min(cp[2], TCP_MAX_WINSHIFT);
				break;
			default:
			continue;
		}
	}
}
#endif

static int
dissect_xstream(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
	//proto_item *expert_ti;
    proto_tree *xstream_tree;
	tvbuff_t *next_tvb;

	//proto_item *next_ti = NULL;
	//proto_item *off_ti = NULL;

	guint8 off = tvb_get_guint8(tvb, XSTREAM_OFF) << 2;
	guint32 seq = tvb_get_ntohl(tvb, XSTREAM_SEQNO);
	guint32 ack = tvb_get_ntohl(tvb, XSTREAM_ACKNO);
	guint32 win = tvb_get_ntohl(tvb, XSTREAM_WIN);


    if (tvb_reported_length(tvb) < XSTREAM_MIN_LENGTH)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Xstream");
    col_set_str(pinfo->cinfo, COL_INFO, "XIA XStream Packet");

    ti = proto_tree_add_item(tree, proto_xstream, tvb, 0, off, ENC_NA);

    xstream_tree = proto_item_add_subtree(ti, ett_xstream);

	//next_ti = proto_tree_add_item(xstream_tree, hf_xstream_next_hdr, tvb,
	proto_tree_add_item(xstream_tree, hf_xstream_next_hdr, tvb,
		XSTREAM_NXTH, 1, ENC_BIG_ENDIAN);

	proto_tree_add_item(xstream_tree, hf_xstream_off, tvb,
		XSTREAM_OFF, 1, ENC_BIG_ENDIAN);

	proto_tree_add_item(xstream_tree, hf_xstream_flags, tvb,
		XSTREAM_FLAGS, 2, ENC_BIG_ENDIAN);

	proto_tree_add_uint(xstream_tree, hf_xstream_seqno, tvb,
		XSTREAM_SEQNO, 4, seq);

	proto_tree_add_uint(xstream_tree, hf_xstream_ackno, tvb,
		XSTREAM_ACKNO, 4, ack);

	proto_tree_add_uint(xstream_tree, hf_xstream_win, tvb,
		XSTREAM_WIN, 4, win);

	proto_tree_add_item(xstream_tree, hf_xstream_opts, tvb,
		XSTREAM_OPTS, off - 16, ENC_BIG_ENDIAN);

	// everything else is data
	next_tvb = tvb_new_subset_remaining(tvb, off);
	call_data_dissector(next_tvb, pinfo, tree);

    /* Some fields or situations may require "expert" analysis that can be
     * specifically highlighted. */
//    if ( TEST_EXPERT_condition )
//        /* value of hf_xstream_FIELDABBREV isn't what's expected */
//        expert_add_info(pinfo, expert_ti, &ei_xstream_EXPERTABBREV);

    return tvb_captured_length(tvb);
}

void
proto_register_xstream(void)
{
//    expert_module_t *expert_xstream;

    static hf_register_info hf[] = {
		{ &hf_xstream_next_hdr,
		{ "Next Header", "xstream.next_hdr", FT_UINT8,
		   BASE_HEX, next_header_vals, 0x0, NULL, HFILL }},

		{ &hf_xstream_off,
		{ "Data Offset (in dwords)", "xstream.off", FT_UINT8,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

   		{ &hf_xstream_flags,
   		{ "Flags", "xstream.flags", FT_UINT16,
   		   BASE_HEX, NULL, 0x0,	NULL, HFILL }},

		{ &hf_xstream_seqno,
		{ "Sequence #", "xstream.seq_no", FT_UINT32,
			BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		{ &hf_xstream_ackno,
		{ "Ack #", "xstream.ack_no", FT_UINT32,
			BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		{ &hf_xstream_win,
		{ "Window", "xstream.win", FT_UINT32,
			BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		{ &hf_xstream_opts,
		{ "Options", "xstream.options", FT_BYTES,
			BASE_NONE, NULL, 0x0,	NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_xstream
    };

//    static ei_register_info ei[] = {
//		{ &ei_xstream_next_header,
//		{ "xstream.next.header", PI_MALFORMED, PI_WARNING,
//		  "Unknown next header", EXPFILL }},
//
//		{ &ei_xstream_invalid_len,
//		{ "xstream.invalid.len", PI_MALFORMED, PI_ERROR,
//		  "Invalid length", EXPFILL }},
//    };

    proto_xstream = proto_register_protocol("XIA XStream", "XStream", "xstream");

    proto_register_field_array(proto_xstream, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

	xstream_handle = register_dissector("xstream", dissect_xstream,
		proto_xstream);

//    expert_xstream = expert_register_protocol(proto_xstream);
//    expert_register_field_array(expert_xstream, ei, array_length(ei));
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
