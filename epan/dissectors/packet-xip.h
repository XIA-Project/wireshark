/* packet-xip.h
 * Routines for XIP dissection
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
 *
 * The eXpressive Internet Protocol (XIP) is the network layer protocol for
 * the eXpressive Internet Architecture (XIA), a future Internet architecture
 * project. The addresses in XIP are directed acyclic graphs, so some of the
 * code in this file verifies the correctness of the DAGs and displays them
 * in human-readable form.
 *
 * More information about XIA can be found here:
 *  https://www.cs.cmu.edu/~xia/
 *
 * And here:
 *  https://github.com/AltraMayor/XIA-for-Linux/wiki
 *
 * More information about the format of the DAG can be found here:
 *  https://github.com/AltraMayor/XIA-for-Linux/wiki/Human-readable-XIP-address-format
 */
#ifndef __PACKET_XIP_H
#define __PACKET_XIP_H

#define ETHERTYPE_XIP   0xC0DE
#define ETHERTYPE_XARP  0x9990
#define ETHERTYPE_XNETJ 0x9991

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

/* XIP next header IDs */
#define XIA_NEXT_HEADER_DATA    0
#define XIA_NEXT_HEADER_XCMP    0x01
#define XIA_NEXT_HEADER_XDGRAM  0x02
#define XIA_NEXT_HEADER_XSTREAM 0x03

extern const value_string xidtype_vals[];
extern const value_string next_header_vals[];

#endif
