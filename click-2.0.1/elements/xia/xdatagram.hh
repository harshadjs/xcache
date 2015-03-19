#ifndef CLICK_XDATAGRAM_HH
#define CLICK_XDATAGRAM_HH

#include <click/element.hh>
#include <clicknet/xia.h>
#include <click/xid.hh>
#include <click/xiaheader.hh>
#include <click/hashtable.hh>
#include "xiaxidroutetable.hh"
#include <click/handlercall.hh>
#include <click/xiapath.hh>
#include <clicknet/xia.h>
#include "xiacontentmodule.hh"
#include "xiaxidroutetable.hh"
#include <clicknet/udp.h>
#include <click/string.hh>
#include <elements/ipsec/sha1_impl.hh>
#include <click/xiatransportheader.hh>
#include "xtransport.hh"

#if CLICK_USERLEVEL
#include <list>
#include <stdio.h>
#include <iostream>
#include <click/xidpair.hh>
#include <click/timer.hh>
#include <click/packet.hh>
#include <queue>
#include "../../userlevel/xia.pb.h"

using namespace std;
using namespace xia;
#endif

// FIXME: put these in a std location that can be found by click and the API
#define XOPT_HLIM 0x07001
#define XOPT_NEXT_PROTO 0x07002

#ifndef DEBUG
#define DEBUG 0
#endif


#define UNUSED(x) ((void)(x))

#define ACK_DELAY			300
#define TEARDOWN_DELAY		240000
#define HLIM_DEFAULT		250
#define LAST_NODE_DEFAULT	-1
#define RANDOM_XID_FMT		"%s:30000ff0000000000000000000000000%08x"
#define UDP_HEADER_SIZE		8

#define XSOCKET_INVALID -1	// invalid socket type	
#define XSOCKET_STREAM	1	// Reliable transport (SID)
#define XSOCKET_DGRAM	2	// Unreliable transport (SID)
#define XSOCKET_RAW		3	// Raw XIA socket
#define XSOCKET_CHUNK	4	// Content Chunk transport (CID)

// TODO: switch these to bytes, not packets?
#define MAX_SEND_WIN_SIZE 256  // in packets, not bytes
#define MAX_RECV_WIN_SIZE 256
#define DEFAULT_SEND_WIN_SIZE 128
#define DEFAULT_RECV_WIN_SIZE 128

#define MAX_CONNECT_TRIES	 30
#define MAX_RETRANSMIT_TRIES 100


CLICK_DECLS


class XIAContentModule;   

class XDatagram : public XGenericTransport {

public:
	XDatagram(XTRANSPORT *transport, unsigned short port);
	~XDatagram() {};
	int read_from_recv_buf(XSocketMsg *xia_socket_msg);
private:

	void push(WritablePacket *p_in);
	bool should_buffer_received_packet(WritablePacket *p);
	void add_packet_to_recv_buf(WritablePacket *p);
	void check_for_and_handle_pending_recv();

	// receive buffer
	WritablePacket *recv_buffer[MAX_RECV_WIN_SIZE]; // packets we've received but haven't delivered to the app // TODO: start smaller, dynamically resize if app asks for more space (up to MAX)?
	uint32_t recv_buffer_size; // the number of PACKETS we can buffer (received but not delivered to app)
	uint32_t recv_base; // sequence # of the oldest received packet not delivered to app
	uint32_t next_recv_seqnum; // the sequence # of the next in-order packet we expect to receive
	int dgram_buffer_start; // the first undelivered index in the recv buffer (DGRAM only)
	int dgram_buffer_end; // the last undelivered index in the recv buffer (DGRAM only)
	uint32_t recv_buffer_count; // the number of packets in the buffer (DGRAM only)

} ;

CLICK_ENDDECLS

#endif
