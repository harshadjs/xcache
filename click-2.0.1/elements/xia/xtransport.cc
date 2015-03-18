#include "../../userlevel/xia.pb.h"
#include <click/config.h>
#include <click/glue.hh>
#include <click/error.hh>
#include <click/confparse.hh>
#include <click/packet_anno.hh>
#include <click/packet.hh>
#include <click/vector.hh>

#include <click/xiacontentheader.hh>
#include "xiatransport.hh"
#include "xtransport.hh"
#include <click/xiatransportheader.hh>

/*
** FIXME:
** - implement a backoff delay on retransmits so we don't flood the connection
** - fix cid header size issue so we work correctly with the linux version
** - migrate from uisng printf and click_chatter to using the click ErrorHandler class
** - there are still some small memory leaks happening when stream sockets are created/used/closed
**   (problem does not happen if sockets are just opened and closed)
** - fix issue in SYN code with XIDPairToConnectPending (see comment in code for details)
*/


CLICK_DECLS

XTRANSPORT::XTRANSPORT()
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;
	// _id = 0;
	// isConnected = false;

	// _ackdelay_ms = ACK_DELAY;
	// _teardown_wait_ms = TEARDOWN_DELAY;

//	pthread_mutexattr_init(&_lock_attr);
//	pthread_mutexattr_settype(&_lock_attr, PTHREAD_MUTEX_RECURSIVE);
//	pthread_mutex_init(&_lock, &_lock_attr);

	cp_xid_type("SID", &_sid_type);
}


int
XTRANSPORT::configure(Vector<String> &conf, ErrorHandler *errh)
{
	XIAPath local_addr;
	XID local_4id;
	Element* routing_table_elem;
	bool is_dual_stack_router;
	_is_dual_stack_router = false;

	/* Configure tcp relevant information */
	 memset(&_tcpstat, 0, sizeof(_tcpstat)); 
    _errh = errh; 

    /* _empty_note.initialize(Notifier::EMPTY_NOTIFIER, router()); */
    
    _tcp_globals.tcp_keepidle 	    = 120; 
    _tcp_globals.tcp_keepintvl 	    = 120; 
    _tcp_globals.tcp_maxidle   	    = 120; 
    _tcp_globals.tcp_now 		    = 0; 
    _tcp_globals.so_recv_buffer_size = 0x10000; 
    _tcp_globals.tcp_mssdflt	    = 1420; 
    _tcp_globals.tcp_rttdflt	    = TCPTV_SRTTDFLT / PR_SLOWHZ;
    _tcp_globals.so_flags	   	 	= 0; 
    _tcp_globals.so_idletime	    = 0; 
    _verbosity 						= VERB_ERRORS; 

    bool so_flags_array[32]; 
    bool t_flags_array[10]; 
    memset(so_flags_array, 0, 32 * sizeof(bool)); 
    memset(t_flags_array, 0, 10 * sizeof(bool)); 

	if (cp_va_kparse(conf, this, errh,
					 "LOCAL_ADDR", cpkP + cpkM, cpXIAPath, &local_addr,
					 "LOCAL_4ID", cpkP + cpkM, cpXID, &local_4id,
					 "ROUTETABLENAME", cpkP + cpkM, cpElement, &routing_table_elem,
					 "IS_DUAL_STACK_ROUTER", 0, cpBool, &is_dual_stack_router,
					 "IDLETIME", 0, cpUnsigned, &(_tcp_globals.so_idletime),
					"MAXSEG", 	0, cpUnsignedShort, &(_tcp_globals.tcp_mssdflt), 
					"RCVBUF", 	0, cpUnsigned, &(_tcp_globals.so_recv_buffer_size),
					"WINDOW_SCALING", 0, cpUnsigned, &(_tcp_globals.window_scale),
					"USE_TIMESTAMPS", 0, cpBool, &(_tcp_globals.use_timestamp),
					"FIN_AFTER_TCP_FIN",  0, cpBool, &(so_flags_array[8]), 
					"FIN_AFTER_TCP_IDLE", 0, cpBool, &(so_flags_array[9]), 
					"FIN_AFTER_UDP_IDLE", 0, cpBool, &(so_flags_array[10]), 
					"VERBOSITY", 0, cpUnsigned, &(_verbosity), // not sure we need this
					 cpEnd) < 0)
		return -1;

    for (int i = 0; i < 32; i++) { 
	if (so_flags_array[i])
	    _tcp_globals.so_flags |= ( 1 << i ) ; 
    }
    _tcp_globals.so_idletime *= PR_SLOWHZ; 
    if (_tcp_globals.window_scale > TCP_MAX_WINSHIFT) 
		_tcp_globals.window_scale = TCP_MAX_WINSHIFT; 

	_local_addr = local_addr;
	_local_hid = local_addr.xid(local_addr.destination_node());
	_local_4id = local_4id;
	// IP:0.0.0.0 indicates NULL 4ID
	_null_4id.parse("IP:0.0.0.0");

	_is_dual_stack_router = is_dual_stack_router;

	/*
	// If a valid 4ID is given, it is included (as a fallback) in the local_addr
	if(_local_4id != _null_4id) {
		String str_local_addr = _local_addr.unparse();
		size_t AD_found_start = str_local_addr.find_left("AD:");
		size_t AD_found_end = str_local_addr.find_left(" ", AD_found_start);
		String AD_str = str_local_addr.substring(AD_found_start, AD_found_end - AD_found_start);
		String HID_str = _local_hid.unparse();
		String IP4ID_str = _local_4id.unparse();
		String new_local_addr = "RE ( " + IP4ID_str + " ) " + AD_str + " " + HID_str;
		//click_chatter("new address is - %s", new_local_addr.c_str());
		_local_addr.parse(new_local_addr);
	}
	*/

#if USERLEVEL
	_routeTable = dynamic_cast<XIAXIDRouteTable*>(routing_table_elem);
#else
	_routeTable = reinterpret_cast<XIAXIDRouteTable*>(routing_table_elem);
#endif

	return 0;
}

// this will be modified later
XTRANSPORT::~XTRANSPORT()
{
	//Clear all hashtable entries
	XIDtoPort.clear();
	portToSock.clear();
	XIDpairToPort.clear();
	XIDpairToConnectPending.clear();

	hlim.clear();
	xcmp_listeners.clear();
	nxt_xport.clear();

//	pthread_mutex_destroy(&_lock);
//	pthread_mutexattr_destroy(&_lock_attr);
}


int
XTRANSPORT::initialize(ErrorHandler *)
{
	_fast_ticks = new Timer(this);
	_fast_ticks->initialize(this);
	_fast_ticks->schedule_after_msec(TCP_FAST_TICK_MS); 
	
	_slow_ticks = new Timer(this);
	_slow_ticks->initialize(this);
	_slow_ticks->schedule_after_msec(TCP_SLOW_TICK_MS); 

	_errh = errh; 

	//_timer.schedule_after_msec(1000);
	//_timer.unschedule();
	return 0;
}

char *XTRANSPORT::random_xid(const char *type, char *buf)
{
	// This is a stand-in function until we get certificate based names
	//
	// note: buf must be at least 45 characters long
	// (longer if the XID type gets longer than 3 characters)
	sprintf(buf, RANDOM_XID_FMT, type, click_random(0, 0xffffffff));

	return buf;
}

void XTRANSPORT::push(int port, Packet *p_input)
{
//	pthread_mutex_lock(&_lock);

	WritablePacket *p_in = p_input->uniqueify();
	//Depending on which CLICK-module-port it arrives at it could be control/API traffic/Data traffic

	switch(port) { // This is a "CLICK" port of UDP module.
	case API_PORT:	// control packet from socket API
		ProcessAPIPacket(p_in);
		break;

	case NETWORK_PORT: //Packet from network layer
		ProcessNetworkPacket(p_in);
		p_in->kill();
		break;

	case CACHE_PORT:	//Packet from cache
		ProcessCachePacket(p_in);
		p_in->kill();
		break;

	case XHCP_PORT:		//Packet with DHCP information
		ProcessXhcpPacket(p_in);
		p_in->kill();
		break;

	case BAD_PORT: //packet from ???
	default:
		click_chatter("packet from unknown port or bad port: %d\n", port);
		break;
	}

//	pthread_mutex_unlock(&_lock);
}

void
XTRANSPORT::run_timer(Timer *t) 
{ 
    ConnIterator i = pairToHandler.begin(); 
    XStream *con = NULL; 

    if (t == _fast_ticks) {
		for (; i; i++) {
			if (i.get_type() == XSOCKET_STREAM)
			{
				con = dynamic_cast<XStream *>(i->second);
				con->fasttimo(); 
			}
		}
		_fast_ticks->reschedule_after_msec(TCP_FAST_TICK_MS);
    } else if (t == _slow_ticks) {
		for (; i; i++) {
			if (i.get_type() == XSOCKET_STREAM)
			{
			con = dynamic_cast<XStream *>(i->second);
			con->slowtimo(); 
			if (con->state() == TCPS_CLOSED) {
				delete con;
				break;
			}
		}
		}
		_slow_ticks->reschedule_after_msec(TCP_SLOW_TICK_MS);
		(globals()->tcp_now)++; 
    } else {
		debug_output(VERB_TIMERS, "%u: XTRANSPORT::run_timer: unknown timer", tcp_now()); 
	}
}

void XTRANSPORT::copy_common(XStream *tcp_conn, XIAHeader &xiahdr, XIAHeaderEncap &xiah) {

	//Recalculate source path
	XID	source_xid = tcp_conn->src_path.xid(tcp_conn->src_path.destination_node());
	String str_local_addr = _local_addr.unparse_re() + " " + source_xid.unparse();
	//Make source DAG _local_addr:SID
	String dagstr = tcp_conn->src_path.unparse_re();

	//Client Mobility...
	if (dagstr.length() != 0 && dagstr != str_local_addr) {
		//Moved!
		// 1. Update 'tcp_conn->src_path'
		tcp_conn->src_path.parse_re(str_local_addr);
	}

	xiah.set_nxt(xiahdr.nxt());
	xiah.set_last(xiahdr.last());
	xiah.set_hlim(xiahdr.hlim());
	xiah.set_dst_path(tcp_conn->dst_path);
	xiah.set_src_path(tcp_conn->src_path);
	xiah.set_plen(xiahdr.plen());
}

WritablePacket *
XTRANSPORT::copy_packet(Packet *p, XStream *tcp_conn) {

	XIAHeader xiahdr(p);
	XIAHeaderEncap xiah;
	copy_common(tcp_conn, xiahdr, xiah);

	TransportHeader thdr(p);
	TransportHeaderEncap *new_thdr = new TransportHeaderEncap(thdr.type(), thdr.pkt_info(), thdr.seq_num(), thdr.ack_num(), thdr.length(), thdr.recv_window());

	WritablePacket *copy = WritablePacket::make(256, thdr.payload(), xiahdr.plen() - thdr.hlen(), 20);

	copy = new_thdr->encap(copy);
	copy = xiah.encap(copy, false);
	delete new_thdr;

	return copy;
}


WritablePacket *
XTRANSPORT::copy_cid_req_packet(Packet *p, XStream *tcp_conn) {

	XIAHeader xiahdr(p);
	XIAHeaderEncap xiah;
	copy_common(tcp_conn, xiahdr, xiah);

	WritablePacket *copy = WritablePacket::make(256, xiahdr.payload(), xiahdr.plen(), 20);

	ContentHeaderEncap *chdr = ContentHeaderEncap::MakeRequestHeader();

	copy = chdr->encap(copy);
	copy = xiah.encap(copy, false);
	delete chdr;
	xiah.set_plen(xiahdr.plen());

	return copy;
}


WritablePacket *
XTRANSPORT::copy_cid_response_packet(Packet *p, XStream *tcp_conn) {

	XIAHeader xiahdr(p);
	XIAHeaderEncap xiah;
	copy_common(tcp_conn, xiahdr, xiah);

	WritablePacket *copy = WritablePacket::make(256, xiahdr.payload(), xiahdr.plen(), 20);

	ContentHeader chdr(p);
	ContentHeaderEncap *new_chdr = new ContentHeaderEncap(chdr.opcode(), chdr.chunk_offset(), chdr.length());

	copy = new_chdr->encap(copy);
	copy = xiah.encap(copy, false);
	delete new_chdr;
	xiah.set_plen(xiahdr.plen());

	return copy;
}

void XTRANSPORT::ProcessNetworkPacket(WritablePacket *p_in)
{

	XIAHeader xiah(p_in->xia_header());
	XIAPath dst_path = xiah.dst_path();
	XIAPath src_path = xiah.src_path();
	XID _destination_xid(xiah.hdr()->node[xiah.last()].xid);
	XID	_source_xid = src_path.xid(src_path.destination_node());
	
	XIDpair xid_pair;
	xid_pair.set_src(_destination_xid);
	xid_pair.set_dst(_source_xid);

	if (xiah.nxt() == CLICK_XIA_NXT_XCMP) { // TODO:  Should these be put in recv buffer???

		String src_path = xiah.src_path().unparse();
		String header((const char*)xiah.hdr(), xiah.hdr_size());
		String payload((const char*)xiah.payload(), xiah.plen());
		String str = header + payload;

		XSocketMsg xsm;
		xsm.set_type(XRECV);
		X_Recvfrom_Msg *x_recvfrom_msg = xsm.mutable_x_recvfrom();
		x_recvfrom_msg->set_sender_dag(src_path.c_str());
		x_recvfrom_msg->set_payload(str.c_str(), str.length());

		std::string p_buf;
		xsm.SerializeToString(&p_buf);

		WritablePacket *xcmp_pkt = WritablePacket::make(256, p_buf.c_str(), p_buf.size(), 0);

		list<int>::iterator i;

		for (i = xcmp_listeners.begin(); i != xcmp_listeners.end(); i++) {
			int port = *i;
			output(API_PORT).push(UDPIPPrep(xcmp_pkt, port));
		}
		return;
	}

	XGenericTransport *handler = pairToHandler.get(xid_pair);
	if (handler != NULL)
	{
		handler -> push(p_in);
	}
	else if (handler == NULL && thdr.type() == TransportHeader::XSOCK_DGRAM)
	{
		XIDpair xid_half_pair;
		xid_half_pair.set_src(_destination_xid);
		udp_handler = pairToHandler.get(xid_pair);
		if (udp_handler != NULL)
		{
			udp_handler = dynamic_cast<XDatagram *>(udp_handler);
			udp_handler -> set_src_path(dst_path);
			udp_handler -> set_dst_path(src_path);
			udp_handler -> set_key(xid_pair);
			pairToHandler.set(xid_pair, udp_handler);
			portToHandler.set(udp_handler -> get_port(), udp_handler);
			udp_handler -> push(p_in)
		} else {
			p_in -> kill();
		}
		return;
	} else if (handler == NULL && thdr.type() == TransportHeader::XSOCK_STREAM) {
		TransportHeader thdr(p_in);
		click_tcp *tcph = thdr.header();
		XIDpair xid_half_pair;
		xid_half_pair.set_src(_destination_xid);
		handler = dynamic_cast<XStream *>(pairToHandler.get(xid_half_pair));
		if (tcph->th_flags == TH_SYN && handler != NULL)
		{
			handler -> set_src_path(dst_path);
			handler -> set_dst_path(src_path);
			handler -> set_key(xid_pair);
			pairToHandler.set(xid_pair, handler);
			portToHandler.set(handler -> get_port(), handler);
			handler -> push(p_in);
		} else {
			// Send a RST packet to signal half open TCP connection
			WritablePacket *p = NULL;
			//Add XIA headers
			XIAHeaderEncap xiah_new;
			xiah_new.set_nxt(CLICK_XIA_NXT_TRN);
			xiah_new.set_last(LAST_NODE_DEFAULT);
			xiah_new.set_hlim(HLIM_DEFAULT);
			xiah_new.set_dst_path(src_path);
			xiah_new.set_src_path(dst_path);
			
			click_tcp rst_tcph;
			click_tcp *tcph = thdr.header();
			rst_tcph.th_off = (sizeof(click_tcp)) >> 2;
		    rst_tcph.th_ack = tcph->th_seq; 
		    rst_tcph.th_seq = tcph->th_ack; 
		    rst_tcph.th_flags = TH_RST; 
		    TransportHeaderEncap *reset = TransportHeaderEncap::MakeTCPHeader(&rst_tcph);
			p = reset -> encap(NULL);
			reset.update();
			xiah_new.set_plen(reset->hlen()); // XIA payload = transport header
			p = xiah_new.encap(p, false);
			delete reset;
			output(NETWORK_PORT).push(p);
		}
	} else {
		p_in -> kill();
	}
	
}

void XTRANSPORT::ProcessXhcpPacket(WritablePacket *p_in)
{
	XIAHeader xiah(p_in->xia_header());
	String temp = _local_addr.unparse();
	Vector<String> ids;
	cp_spacevec(temp, ids);;
	if (ids.size() < 3) {
		String new_route((char *)xiah.payload());
		String new_local_addr = new_route + " " + ids[1];
		click_chatter("new address is - %s", new_local_addr.c_str());
		_local_addr.parse(new_local_addr);
	}
}

/*********************************** socket API functions *******************************/
/*********************************** socket API functions *******************************/
/*********************************** socket API functions *******************************/
/*********************************** socket API functions *******************************/
/*********************************** socket API functions *******************************/
/*********************************** socket API functions *******************************/
/*********************************** socket API functions *******************************/
/*********************************** socket API functions *******************************/
/*********************************** socket API functions *******************************/
/*********************************** socket API functions *******************************/
/*********************************** socket API functions *******************************/
/*********************************** socket API functions *******************************/
/*********************************** socket API functions *******************************/
/*********************************** socket API functions *******************************/


void XTRANSPORT::ProcessAPIPacket(WritablePacket *p_in)
{
	//Extract the destination port
	unsigned short _sport = SRC_PORT_ANNO(p_in);

//	if (DEBUG)
//      click_chatter("\nPush: Got packet from API sport:%d",ntohs(_sport));

	std::string p_buf;
	p_buf.assign((const char*)p_in->data(), (const char*)p_in->end_data());

	//protobuf message parsing
	XSocketMsg xia_socket_msg;
	xia_socket_msg.ParseFromString(p_buf);

	switch(xia_socket_msg.type()) {
	case XSOCKET:
		Xsocket(_sport, &xia_socket_msg);
		break;
	case XSETSOCKOPT:
		Xsetsockopt(_sport, &xia_socket_msg);
		break;
	case XGETSOCKOPT:
		Xgetsockopt(_sport, &xia_socket_msg);
		break;
	case XBIND:
		Xbind(_sport, &xia_socket_msg);
		break;
	case XCLOSE:
		Xclose(_sport, &xia_socket_msg);
		break;
	case XCONNECT:
		Xconnect(_sport, &xia_socket_msg);
		break;
	case XREADYTOACCEPT:
		XreadyToAccept(_sport, &xia_socket_msg);
		break;
	case XACCEPT:
		Xaccept(_sport, &xia_socket_msg);
		break;
	case XCHANGEAD:
		Xchangead(_sport, &xia_socket_msg);
		break;
	case XREADLOCALHOSTADDR:
		Xreadlocalhostaddr(_sport, &xia_socket_msg);
		break;
	case XUPDATENAMESERVERDAG:
		Xupdatenameserverdag(_sport, &xia_socket_msg);
		break;
	case XREADNAMESERVERDAG:
		Xreadnameserverdag(_sport, &xia_socket_msg);
		break;
	case XISDUALSTACKROUTER:
		Xisdualstackrouter(_sport, &xia_socket_msg);
		break;
    case XSEND:
		Xsend(_sport, &xia_socket_msg, p_in);
		break;
	case XSENDTO:
		Xsendto(_sport, &xia_socket_msg, p_in);
		break;
	case XRECV:
		Xrecv(_sport, &xia_socket_msg);
		break;
	case XRECVFROM:
		Xrecvfrom(_sport, &xia_socket_msg);
		break;
	case XREQUESTCHUNK:
		XrequestChunk(_sport, &xia_socket_msg, p_in);
		break;
	case XGETCHUNKSTATUS:
		XgetChunkStatus(_sport, &xia_socket_msg);
		break;
	case XREADCHUNK:
		XreadChunk(_sport, &xia_socket_msg);
		break;
	case XREMOVECHUNK:
		XremoveChunk(_sport, &xia_socket_msg);
		break;
	case XPUTCHUNK:
		XputChunk(_sport, &xia_socket_msg);
		break;
	case XGETPEERNAME:
		Xgetpeername(_sport, &xia_socket_msg);
		break;
	case XGETSOCKNAME:
		Xgetsockname(_sport, &xia_socket_msg);
		break;
	case XPOLL:
		Xpoll(_sport, &xia_socket_msg);
		break;
	default:
		click_chatter("\n\nERROR: API TRAFFIC !!!\n\n");
		break;
	}

	p_in->kill();
}

void XTRANSPORT::ReturnResult(int sport, XSocketMsg *xia_socket_msg, int rc, int err)
{
//	click_chatter("sport=%d type=%d rc=%d err=%d\n", sport, type, rc, err);
	X_Result_Msg *x_result = xia_socket_msg->mutable_x_result();
	x_result->set_return_code(rc);
	x_result->set_err_code(err);

	std::string p_buf;
	xia_socket_msg->SerializeToString(&p_buf);
	WritablePacket *reply = WritablePacket::make(256, p_buf.c_str(), p_buf.size(), 0);
	output(API_PORT).push(UDPIPPrep(reply, sport));
}

Packet *
XTRANSPORT::UDPIPPrep(Packet *p_in, int dport)
{
    p_in->set_dst_ip_anno(IPAddress("127.0.0.1"));
    SET_DST_PORT_ANNO(p_in, dport);

	return p_in;
}


enum {H_MOVE};

int XTRANSPORT::write_param(const String &conf, Element *e, void *vparam,
							ErrorHandler *errh)
{
	XTRANSPORT *f = static_cast<XTRANSPORT *>(e);
	switch(reinterpret_cast<intptr_t>(vparam)) {
	case H_MOVE:
	{
		XIAPath local_addr;
		if (cp_va_kparse(conf, f, errh,
						 "LOCAL_ADDR", cpkP + cpkM, cpXIAPath, &local_addr,
						 cpEnd) < 0)
			return -1;
		f->_local_addr = local_addr;
		click_chatter("Moved to %s", local_addr.unparse().c_str());
		f->_local_hid = local_addr.xid(local_addr.destination_node());

	}
	break;
	default:
		break;
	}
	return 0;
}

void XTRANSPORT::add_handlers() {
	add_write_handler("local_addr", write_param, (void *)H_MOVE);
}

/*
** Handler for the Xsocket API call
**
** FIXME: why is xia_socket_msg part of the xtransport class and not a local variable?????
*/
void XTRANSPORT::Xsocket(unsigned short _sport, XSocketMsg *xia_socket_msg) {
	//Open socket.
	click_chatter("Xsocket: create socket %d\n", _sport);
	printf("Xsocket: create socket %d\n", _sport);

	X_Socket_Msg *x_socket_msg = xia_socket_msg->mutable_x_socket();
	int sock_type = x_socket_msg->type();
	XGenericTransport *handler;
	
	switch (sock_type) {
		case XSOCKET_STREAM:
		handler = XStream(this, _sport);
		break;
		case XSOCKET_DGRAM:
		handler = XDatagram(this, _sport);
		break;
		case XSOCKET_CHUNK:
		handler = XChunk(this, _sport);
		break;
		default:
		break;
	}
	portToHandler.set(_sport, handler);
	
	// Return result to API
	ReturnResult(_sport, xia_socket_msg, 0);
}

/*
** Xsetsockopt API handler
*/
void XTRANSPORT::Xsetsockopt(unsigned short _sport, XSocketMsg *xia_socket_msg) {

	// click_chatter("\nSet Socket Option\n");
	X_Setsockopt_Msg *x_sso_msg = xia_socket_msg->mutable_x_setsockopt();
	XGenericTransport *handler = portToHandler.get(_sport);
	XIDPair pair = handler -> get_key();
	switch (x_sso_msg->opt_type())
	{
	case XOPT_HLIM:
	{
		int hl = x_sso_msg->int_opt();
		handler -> set_hlim(hl);

		//click_chatter("sso:hlim:%d\n",hl);
	}
	break;

	case XOPT_NEXT_PROTO:
	{
		int nxt = x_sso_msg->int_opt();
		handler -> set_nxt(nxt);
		if (nxt == CLICK_XIA_NXT_XCMP)
			xcmp_listeners.push_back(_sport);
		else
			xcmp_listeners.remove(_sport);
	}
	break;

	default:
		// unsupported option
		break;
	}
	portToHandler.set(_sport, handler);
	pairToHandler.set(key, handler);
	ReturnResult(_sport, xia_socket_msg); // TODO: return code
}

/*
** Xgetsockopt API handler
*/
void XTRANSPORT::Xgetsockopt(unsigned short _sport, XSocketMsg *xia_socket_msg) {
	// click_chatter("\nGet Socket Option\n");
	X_Getsockopt_Msg *x_sso_msg = xia_socket_msg->mutable_x_getsockopt();

	// click_chatter("opt = %d\n", x_sso_msg->opt_type());
	XGenericTransport *handler = portToHandler.get(_sport);
	switch (x_sso_msg->opt_type())
	{
	case XOPT_HLIM:
	{
		x_sso_msg->set_int_opt(handler->get_hlim());
		//click_chatter("gso:hlim:%d\n", hlim.get(_sport));
	}
	break;

	case XOPT_NEXT_PROTO:
	{
		x_sso_msg->set_int_opt(handler->get_nxt());
	}
	break;

	default:
		// unsupported option
		break;
	}

	ReturnResult(_sport, xia_socket_msg); // TODO: return code
}

void XTRANSPORT::Xbind(unsigned short _sport, XSocketMsg *xia_socket_msg) {

	int rc = 0, ec = 0;


	//Bind XID
	//click_chatter("\n\nOK: SOCKET BIND !!!\\n");
	//get source DAG from protobuf message

	X_Bind_Msg *x_bind_msg = xia_socket_msg->mutable_x_bind();

	String sdag_string(x_bind_msg->sdag().c_str(), x_bind_msg->sdag().size());

	//String sdag_string((const char*)p_in->data(),(const char*)p_in->end_data());
//	if (DEBUG)
//		click_chatter("\nbind requested to %s, length=%d\n", sdag_string.c_str(), (int)p_in->length());

	//String str_local_addr=_local_addr.unparse();
	//str_local_addr=str_local_addr+" "+xid_string;//Make source DAG _local_addr:SID

	//Set the source DAG in sock
	XGenericTransport *handler = portToHandler.get(_sport);
	if (handler == NULL)
	{
		// error case
		return;
	}

	if (handler->get_src_path().parse(sdag_string)) {
		handler->set_nxt(LAST_NODE_DEFAULT);
		handler->set_last(LAST_NODE_DEFAULT);

		// handler->sdag = sdag_string;

		//Check if binding to full DAG or just to SID only
		Vector<XIAPath::handle_t> xids = handler->get_src_path().next_nodes( handler->get_src_path().source_node() );
		XID front_xid = handler->get_src_path().xid( xids[0] );
		struct click_xia_xid head_xid = front_xid.xid();
		uint32_t head_xid_type = head_xid.type;
		if(head_xid_type == _sid_type) {
			handler->set_full_src_dag(false);
		} else {
			handler->set_full_src_dag(true);
		}

		XID	source_xid = handler->get_src_path().xid(handler->get_src_path().destination_node());
		//XID xid(xid_string);
		//TODO: Add a check to see if XID is already being used

		// Map the source XID to source port (for now, for either type of tranports)
		
		addRoute(source_xid);
//		printf("Xbind, S2P %d, %p\n", _sport, handler);
		// portToSock.set(_sport, handler);
		portToHandler.set(_sport, handler);

		XIDpair xid_pair;
		xid_pair.set_src(source_xid);
		pairToHandler.set(xid_pair, handler);
		//click_chatter("Bound");
		//click_chatter("set %d %d",_sport, __LINE__);

	} else {
		rc = -1;
		ec = EADDRNOTAVAIL;
	}
	
	ReturnResult(_sport, xia_socket_msg, rc, ec);
}

void XTRANSPORT::Xclose(unsigned short _sport, XSocketMsg *xia_socket_msg)
{
	// Close port
	//click_chatter("Xclose: closing %d\n", _sport);

	// sock *sk = portToSock.get(_sport);

	// // Set timer
	// sk->timer_on = true;
	// sk->teardown_waiting = true;
	// sk->teardown_expiry = Timestamp::now() + Timestamp::make_msec(_teardown_wait_ms);

	// if (! _timer.scheduled() || _timer.expiry() >= sk->teardown_expiry )
	// 	_timer.reschedule_at(sk->teardown_expiry);

	// portToSock.set(_sport, sk);
	XGenericTransport *handler = portToHandler.get(_sport);
	if (handler == NULL)
	{
		// error case
		return;
	}
	if (handler -> get_type() == XSOCKET_STREAM) {
		dynamic_cast<XStream *>(handler) -> usrclosed();
	}
	// shall we remove key value pair from here??
	xcmp_listeners.remove(_sport);
	XIDPair pair = handler -> get_key();
	pairToHandler.remove(pair);
	portToHandler.remove(_sport);

	ReturnResult(_sport, xia_socket_msg);
}

void XTRANSPORT::Xconnect(unsigned short _sport, XSocketMsg *xia_socket_msg)
{
	//click_chatter("Xconect: connecting %d\n", _sport);

	//isConnected=true;
	//String dest((const char*)p_in->data(),(const char*)p_in->end_data());
	//click_chatter("\nconnect to %s, length=%d\n",dest.c_str(),(int)p_in->length());

	X_Connect_Msg *x_connect_msg = xia_socket_msg->mutable_x_connect();

	String dest(x_connect_msg->ddag().c_str());

	//String sdag_string((const char*)p_in->data(),(const char*)p_in->end_data());
	//click_chatter("\nconnect requested to %s, length=%d\n",dest.c_str(),(int)p_in->length());

	XIAPath dst_path;
	dst_path.parse(dest);

	XGenericTransport *handler = portToHandler.get(_sport);
	XIDPair old_key = handler -> get_key();
	//click_chatter("connect %d %x",_sport, sk);

	if(handler == NULL) {
		//click_chatter("Create DAGINFO connect %d %x",_sport, sk);
		//No local SID bound yet, so bind ephemeral one
		// error case??
		return ;
	} 
	if (handler ->get_type() == XSOCKET_STREAM){
		XStream *tcp_conn = dynamic_cast<XStream *>handler;
		if (tcp_conn -> tp->t_state == TCPS_SYN_SENT) {
			// a connect is already in progress
			x_connect_msg->set_status(X_Connect_Msg::XCONNECTING);
			ReturnResult(_sport, xia_socket_msg, -1, EALREADY);
		}
		tcp_conn->set_dst_path(dst_path);

		String str_local_addr = _local_addr.unparse_re();
		//String dagstr = tcp_conn->src_path.unparse_re();

		/* Use src_path set by Xbind() if exists */
		if(tcp_conn->get_sdag().length() == 0) {
			char xid_string[50];
			random_xid("SID", xid_string);

			str_local_addr = str_local_addr + " " + xid_string; //Make source DAG _local_addr:SID
			tcp_conn->get_src_path().parse_re(str_local_addr);
		}

		tcp_conn->set_nxt(LAST_NODE_DEFAULT);
		tcp_conn->set_last(LAST_NODE_DEFAULT);
		tcp_conn->usropen();

		XID source_xid = tcp_conn->get_src_path().xid(tcp_conn->get_src_path().destination_node());
		XID destination_xid = tcp_conn->get_dst_path().xid(tcp_conn->get_dst_path().destination_node());

		XIDpair xid_pair;
		xid_pair.set_src(source_xid);
		xid_pair.set_dst(destination_xid);

		// Map the src & dst XID pair to source port()
		//printf("Xconnect setting pair to port1 %d %s %s\n", _sport, source_xid.unparse().c_str(), destination_xid.unparse().c_str());
		pairToHandler.erase(old_key);
		pairToHandler.set(xid_pair, tcp_conn);
		portToHandler.set(_sport, tcp_conn);
	}
	addRoute(source_xid);

	x_connect_msg->set_status(X_Connect_Msg::XCONNECTING);
	ReturnResult(_sport, xia_socket_msg, -1, EINPROGRESS);
}

void XTRANSPORT::XreadyToAccept(unsigned short _sport, XSocketMsg *xia_socket_msg)
{
	// If there is already a pending connection, return true now
	// If not, add this request to the pendingAccept queue
	sock *sk = portToSock.get(_sport);

	if (!sk->pending_connection_buf.empty()) {
		ReturnResult(_sport, xia_socket_msg);
	} else {
		// xia_socket_msg is saved on the stack; allocate a copy on the heap
		XSocketMsg *xsm_cpy = new XSocketMsg();
		xsm_cpy->CopyFrom(*xia_socket_msg);
		sk->pendingAccepts.push(xsm_cpy);
	}
}

void XTRANSPORT::Xaccept(unsigned short _sport, XSocketMsg *xia_socket_msg)
{
	int rc = 0, ec = 0;
	
	// _sport is the *existing accept socket*
	unsigned short new_port = xia_socket_msg->x_accept().new_port();
	sock *sk = portToSock.get(_sport);

	hlim.set(new_port, HLIM_DEFAULT);
	nxt_xport.set(new_port, CLICK_XIA_NXT_TRN);

	if (!sk->pending_connection_buf.empty()) {
		sock *new_sk = sk->pending_connection_buf.front();
		new_sk->port = new_port;

		new_sk->seq_num = 0;
		new_sk->ack_num = 0;
		new_sk->send_base = 0;
		new_sk->hlim = hlim.get(new_port);
		new_sk->next_send_seqnum = 0;
		new_sk->next_recv_seqnum = 0;
		new_sk->isAcceptSocket = true; // FIXME backwards? shouldn't sk be the accpet socket?
		memset(new_sk->send_buffer, 0, new_sk->send_buffer_size * sizeof(WritablePacket*));
		memset(new_sk->recv_buffer, 0, new_sk->recv_buffer_size * sizeof(WritablePacket*));
		//new_sk->pending_connection_buf = new queue<sock>();
		//new_sk->pendingAccepts = new queue<XSocketMsg*>();

		portToSock.set(new_port, new_sk);

		XID source_xid = new_sk->src_path.xid(new_sk->src_path.destination_node());
		XID destination_xid = new_sk->dst_path.xid(new_sk->dst_path.destination_node());

		XIDpair xid_pair;
		xid_pair.set_src(source_xid);
		xid_pair.set_dst(destination_xid);

		// Map the src & dst XID pair to source port
		XIDpairToPort.set(xid_pair, new_port);
		//printf("Xaccept pair to port %d %s %s\n", _sport, source_xid.unparse().c_str(), destination_xid.unparse().c_str());

		portToActive.set(new_port, true);

		// printf("XACCEPT: (%s) my_new_port=%d  my_sid=%s  his_sid=%s \n\n", (_local_addr.unparse()).c_str(), new_port, source_xid.unparse().c_str(), destination_xid.unparse().c_str());

		sk->pending_connection_buf.pop();

		XIAHeaderEncap xiah_new;
		xiah_new.set_nxt(CLICK_XIA_NXT_TRN);
		xiah_new.set_last(LAST_NODE_DEFAULT);
		xiah_new.set_hlim(HLIM_DEFAULT);
		xiah_new.set_dst_path(new_sk->dst_path);
		xiah_new.set_src_path(new_sk->src_path);

		//printf("Xaccept src: %s\n", new_sk->src_path.unparse().c_str());
		//printf("Xaccept dst: %s\n", new_sk->dst_path.unparse().c_str());

		const char* dummy = "Connection_granted";
		WritablePacket *just_payload_part = WritablePacket::make(256, dummy, strlen(dummy), 0);

		WritablePacket *p = NULL;

		xiah_new.set_plen(strlen(dummy));
		//click_chatter("Sent packet to network");

		TransportHeaderEncap *thdr_new = TransportHeaderEncap::MakeSYNACKHeader( 0, 0, 0, calc_recv_window(new_sk)); // #seq, #ack, length, recv_wind
		p = thdr_new->encap(just_payload_part);

		thdr_new->update();
		xiah_new.set_plen(strlen(dummy) + thdr_new->hlen()); // XIA payload = transport header + transport-layer data

		p = xiah_new.encap(p, false);
		delete thdr_new;
		output(NETWORK_PORT).push(p);

		// Get remote DAG to return to app
		X_Accept_Msg *x_accept_msg = xia_socket_msg->mutable_x_accept();
		x_accept_msg->set_remote_dag(new_sk->dst_path.unparse().c_str()); // remote endpoint is dest from our perspective

	} else {
		rc = -1;
		ec = EWOULDBLOCK;
	}

	ReturnResult(_sport, xia_socket_msg, rc, ec);
}


// note this is only going to return status for a single socket in the poll response
// the only time we will return multiple sockets is when poll returns immediately
void XTRANSPORT::ProcessPollEvent(unsigned short _sport, unsigned int flags_out)
{
	// loop thru all the polls that are registered looking for the socket associated with _sport
	for (HashTable<unsigned short, PollEvent>::iterator it = poll_events.begin(); it != poll_events.end(); it++) {
		unsigned short pollport = it->first;
		PollEvent pe = it->second;

		HashTable<unsigned short, unsigned int>::iterator sevent = pe.events.find(_sport);

		// socket isn't in this poll instance, keep looking
		if (sevent == pe.events.end())
			continue;

		unsigned short port = sevent->first;
		unsigned int mask = sevent->second;

		// if flags_out isn't an error and doesn't match the event mask keep looking
		if (!(flags_out & mask) && !(flags_out & (POLLHUP | POLLERR | POLLNVAL)))
			continue;

		XSocketMsg xsm;
		xsm.set_type(XPOLL);
		X_Poll_Msg *msg = xsm.mutable_x_poll();
		
		X_Poll_Msg::PollFD *pfd = msg->add_pfds();
		pfd->set_flags(flags_out);
		pfd->set_port(port);

		msg->set_nfds(1);

		// do I need to set other flags in the return struct?
		ReturnResult(pollport, &xsm, 1, 0);

		// found the socket, decrement the polling count for all the sockets in the poll instance
		for (HashTable<unsigned short, unsigned int>::iterator pit = pe.events.begin(); pit != pe.events.end(); pit++) {
			port = pit->first;

			XGenericTransport *handler = portToSock.get(port);
			handler ->decrease_polling();
		}

		// get rid of this poll event
		poll_events.erase(it);
	}
}

void XTRANSPORT::CancelPollEvent(unsigned short _sport)
{
	PollEvent pe;
	unsigned short pollport;
	HashTable<unsigned short, PollEvent>::iterator it;

	// loop thru all the polls that are registered looking for the socket associated with _sport
	for (it = poll_events.begin(); it != poll_events.end(); it++) {
		pollport = it->first;
		pe = it->second;

		if (pollport == _sport)
			break;
		pollport = 0;
	}

	if (pollport == 0) {
		// we didn't find any events for this control socket
		// should we report error in this case?
		return;
	}

	// we have the poll event associated with this control socket

	// decrement the polling count for all the sockets in the poll instance
	for (HashTable<unsigned short, unsigned int>::iterator pit = pe.events.begin(); pit != pe.events.end(); pit++) {
		unsigned short port = pit->first;

		XGenericTransport *handler = portToSock.get(port);
		handler -> decrease_polling();
	}

	// get rid of this poll event
	poll_events.erase(it);
}


void XTRANSPORT::CreatePollEvent(unsigned short _sport, X_Poll_Msg *msg)
{
	PollEvent pe;
	uint32_t nfds = msg->nfds();

	// printf("XPOLL Create:\nnfds:%d\n", nfds);

	for (int i = 0; i < nfds; i++) {
		const X_Poll_Msg::PollFD& pfd = msg->pfds(i);

		int port = pfd.port();
		unsigned flags = pfd.flags();

		// ignore ports that are set to 0, or are negative
		if (port <= 0)
			continue;

		// add the socket to this poll event
		pe.events.set(port, flags);
		XGenericTransport *handler = portToSock.get(port);
		handler -> increase_polling();
	}

	// register the poll event 
	poll_events.set(_sport, pe);
}


void XTRANSPORT::Xpoll(unsigned short _sport, XSocketMsg *xia_socket_msg)
{
	X_Poll_Msg *poll_in = xia_socket_msg->mutable_x_poll();

	if (poll_in->type() == X_Poll_Msg::DOPOLL) {

		int actionable = 0;	
		XSocketMsg msg_out;
		msg_out.set_type(XPOLL);
		X_Poll_Msg *poll_out = msg_out.mutable_x_poll();

		unsigned nfds = poll_in->nfds();

		// printf("XPOLL:\nnfds:%d\n", nfds);
		for (int i = 0; i < nfds; i++) {
			const X_Poll_Msg::PollFD& pfd_in = poll_in->pfds(i);

			int port = pfd_in.port();
			unsigned flags = pfd_in.flags();
			// printf("port: %d, flags: %x\n", pfd_in.port(), pfd_in.flags());

			// skip over ignored ports
			if ( port <= 0) {
				// printf("skipping ignored port\n");
				continue;
			}

			XGenericTransport *handler = portToSock.get(port);
			unsigned flags_out = 0;

			if (!handler) {
				// no socket state, we'll return an error right away
				// printf("No socket state found for %d\n", port);
				flags_out = POLLNVAL;
			
			} else {
				// is there any read data?
				if (flags & POLLIN) {
					if (handler->is_recv_pending()) {
						// printf("read data avaialable on %d\n", port);
						flags_out |= POLLIN;
					}
				}

				if (flags & POLLOUT) {
					// see if the socket is writable
					// FIXME should we be looking for anything else (send window, etc...)
					if (handler->get_type() == SOCK_STREAM) {
						if (handler->get_state() == ACTIVE) {
							// printf("stream socket is connected, so setting POLLOUT: %d\n", port);
							flags_out |= POLLOUT;
						}

					} else {
						// printf("assume POLLOUT is always set for datagram sockets: %d\n", port);
						flags_out |= POLLOUT;
					}
				}
			}

			if (flags_out) {
				// the socket can respond to the poll immediately
				X_Poll_Msg::PollFD *pfd_out = poll_out->add_pfds();
				pfd_out->set_flags(flags_out);
				pfd_out->set_port(port);

				actionable++;
			}
		}

		// we can return a result right away
		if (actionable) {
			// printf("returning immediately number of actionable sockets is %d\n", actionable);
			poll_out->set_nfds(actionable);
			ReturnResult(_sport, &msg_out, actionable, 0);
		
		} else {
			// we can't return a result yet
			CreatePollEvent(_sport, poll_in);
		}
	} else { // type == CANCEL
		// cancel the poll(s) on this control socket
		CancelPollEvent(_sport);
	}
}


void XTRANSPORT::Xchangead(unsigned short _sport, XSocketMsg *xia_socket_msg)
{
	UNUSED(_sport);

	X_Changead_Msg *x_changead_msg = xia_socket_msg->mutable_x_changead();
	//String tmp = _local_addr.unparse();
	//Vector<String> ids;
	//cp_spacevec(tmp, ids);
	String AD_str(x_changead_msg->ad().c_str());
	String HID_str = _local_hid.unparse();
	String IP4ID_str(x_changead_msg->ip4id().c_str());
	_local_4id.parse(IP4ID_str);
	String new_local_addr;
	// If a valid 4ID is given, it is included (as a fallback) in the local_addr
	if(_local_4id != _null_4id) {
		new_local_addr = "RE ( " + IP4ID_str + " ) " + AD_str + " " + HID_str;
	} else {
		new_local_addr = "RE " + AD_str + " " + HID_str;
	}
	click_chatter("new address is - %s", new_local_addr.c_str());
	_local_addr.parse(new_local_addr);

	ReturnResult(_sport, xia_socket_msg);
}

void XTRANSPORT::Xreadlocalhostaddr(unsigned short _sport, XSocketMsg *xia_socket_msg)
{
	// read the localhost AD and HID
	String local_addr = _local_addr.unparse();
	size_t AD_found_start = local_addr.find_left("AD:");
	size_t AD_found_end = local_addr.find_left(" ", AD_found_start);
	String AD_str = local_addr.substring(AD_found_start, AD_found_end - AD_found_start);
	String HID_str = _local_hid.unparse();
	String IP4ID_str = _local_4id.unparse();
	// return a packet containing localhost AD and HID
	X_ReadLocalHostAddr_Msg *_msg = xia_socket_msg->mutable_x_readlocalhostaddr();
	_msg->set_ad(AD_str.c_str());
	_msg->set_hid(HID_str.c_str());
	_msg->set_ip4id(IP4ID_str.c_str());

	ReturnResult(_sport, xia_socket_msg);
}

void XTRANSPORT::Xupdatenameserverdag(unsigned short _sport, XSocketMsg *xia_socket_msg)
{
	UNUSED(_sport);

	X_Updatenameserverdag_Msg *x_updatenameserverdag_msg = xia_socket_msg->mutable_x_updatenameserverdag();
	String ns_dag(x_updatenameserverdag_msg->dag().c_str());
	//click_chatter("new nameserver address is - %s", ns_dag.c_str());
	_nameserver_addr.parse(ns_dag);

	ReturnResult(_sport, xia_socket_msg);
}

void XTRANSPORT::Xreadnameserverdag(unsigned short _sport, XSocketMsg *xia_socket_msg)
{
	// read the nameserver DAG
	String ns_addr = _nameserver_addr.unparse();

	// return a packet containing the nameserver DAG
	X_ReadNameServerDag_Msg *_msg = xia_socket_msg->mutable_x_readnameserverdag();
	_msg->set_dag(ns_addr.c_str());

	ReturnResult(_sport, xia_socket_msg);
}

void XTRANSPORT::Xisdualstackrouter(unsigned short _sport, XSocketMsg *xia_socket_msg)
{
	// return a packet indicating whether this node is an XIA-IPv4 dual-stack router
	X_IsDualStackRouter_Msg *_msg = xia_socket_msg->mutable_x_isdualstackrouter();
	_msg->set_flag(_is_dual_stack_router);

	ReturnResult(_sport, xia_socket_msg);
}

void XTRANSPORT::Xgetpeername(unsigned short _sport, XSocketMsg *xia_socket_msg)
{
	XGenericTransport *handler = portToHandler.get(_sport);

	X_GetPeername_Msg *_msg = xia_socket_msg->mutable_x_getpeername();
	_msg->set_dag(handler->dst_path().unparse().c_str());

	ReturnResult(_sport, xia_socket_msg);
}


void XTRANSPORT::Xgetsockname(unsigned short _sport, XSocketMsg *xia_socket_msg)
{
	XGenericTransport *handler = portToHandler.get(_sport);

	X_GetSockname_Msg *_msg = xia_socket_msg->mutable_x_getsockname();
	_msg->set_dag(handler->src_path().unparse().c_str());

	ReturnResult(_sport, xia_socket_msg);
}


void XTRANSPORT::Xsend(unsigned short _sport, XSocketMsg *xia_socket_msg, WritablePacket *p_in)
{
	int rc = 0, ec = 0;
	//click_chatter("Xsend on %d\n", _sport);

	X_Send_Msg *x_send_msg = xia_socket_msg->mutable_x_send();
	int pktPayloadSize = x_send_msg->payload().size();

	//click_chatter("pkt %s port %d", pktPayload.c_str(), _sport);
	//printf("XSEND: %d bytes from (%d)\n", pktPayloadSize, _sport);

	//Find socket state
	XGenericTransport *handler = portToHandler.get(_sport);


	// Make sure the socket state isn't null
	if (rc == 0 && !handler) {
		rc = -1;
		ec = EBADF; // FIXME: is this the right error?
	}

	// Make sure socket is connected
	if (rc == 0 && handler->get_state() != ACTIVE) {
		rc = -1;
		ec = ENOTCONN;
	}

// 	// FIXME: in blocking mode, send should block until buffer space is available.
// 	int numUnACKedSentPackets = sk->next_send_seqnum - sk->send_base;
// 	if (rc == 0 && 
// 		numUnACKedSentPackets >= sk->send_buffer_size &&  // make sure we have space in send buf
// 		numUnACKedSentPackets >= sk->remote_recv_window) { // and receiver has space in recv buf

// //		if (numUnACKedSentPackets >= sk->send_buffer_size)
// //			printf("Not sending -- out of send buf space\n");
// //		else if (numUnACKedSentPackets >= sk->remote_recv_window)
// //			printf("Not sending -- out of recv buf space\n");

// 		rc = 0; // -1;  // set to 0 for now until blocking behavior is fixed
// 		ec = EAGAIN;
// 	}

	// If everything is OK so far, try sending
	if (rc == 0) {
		rc = pktPayloadSize;

		//Recalculate source path
		XID	source_xid = handler->get_src_path().xid(handler->get_src_path().destination_node());
		String str_local_addr = _local_addr.unparse_re() + " " + source_xid.unparse();
		//Make source DAG _local_addr:SID
		String dagstr = handler->get_src_path().unparse_re();

		//Client Mobility...
		if (dagstr.length() != 0 && dagstr != str_local_addr) {
			//Moved!
			// 1. Update 'sk->src_path'
			handler->get_src_path().parse_re(str_local_addr);
		}

		// Case of initial binding to only SID
		if(!handler->is_full_src_dag()) {
			handler->set_full_src_dag(true);
			String str_local_addr = _local_addr.unparse_re();
			XID front_xid = handler->get_src_path().xid(handler->get_src_path().destination_node());
			String xid_string = front_xid.unparse();
			str_local_addr = str_local_addr + " " + xid_string; //Make source DAG _local_addr:SID
			handler->get_src_path().parse_re(str_local_addr);
		}

//		if (DEBUG)
//			click_chatter("XSEND: (%d) sent packet to %s, from %s\n", _sport, sk->dst_path.unparse_re().c_str(), sk->src_path.unparse_re().c_str());

		WritablePacket *payload = WritablePacket::make(p_in->headroom() + 1, (const void*)x_send_msg->payload().c_str(), pktPayloadSize, p_in->tailroom());
		if (handler -> get_type() == XSOCKET_STREAM)
		{
			handler->usrsend(payload);
		} else if (handler -> get_type() == XSOCKET_DGRAM)
		{
			/* code */
		}

	}

	x_send_msg->clear_payload(); // clear payload before returning result
	ReturnResult(_sport, xia_socket_msg, rc, ec);
}

void XTRANSPORT::Xsendto(unsigned short _sport, XSocketMsg *xia_socket_msg, WritablePacket *p_in)
{
	int rc = 0, ec = 0;

	X_Sendto_Msg *x_sendto_msg = xia_socket_msg->mutable_x_sendto();

	String dest(x_sendto_msg->ddag().c_str());
	int pktPayloadSize = x_sendto_msg->payload().size();
	//click_chatter("\n SENDTO ddag:%s, payload:%s, length=%d\n",xia_socket_msg.ddag().c_str(), xia_socket_msg.payload().c_str(), pktPayloadSize);

	XIAPath dst_path;
	dst_path.parse(dest);

	//Find DAG info for this DGRAM
	XGenericTransport *handler = portToHandler.get(_sport);

	if(!handler) {
		//No local SID bound yet, so bind one
		// sk = new sock();
		// treat as error
		return;
	}

	// handler->set_full_src_dag(true);
	// handler->port = _sport;
	// String str_local_addr = _local_addr.unparse_re();

	// char xid_string[50];
	// random_xid("SID", xid_string);
	// str_local_addr = str_local_addr + " " + xid_string; //Make source DAG _local_addr:SID

	// handler->src_path.parse_re(str_local_addr);

	// handler->last = LAST_NODE_DEFAULT;
	// handler->hlim = hlim.get(_sport);

	// XID	source_xid = handler->src_path.xid(handler->src_path.destination_node());

	// XIDtoPort.set(source_xid, _sport); //Maybe change the mapping to XID->sock?
	// addRoute(source_xid);


	// Case of initial binding to only SID
	if(!handler->is_full_src_dag()) {
		handler->set_full_src_dag(true);
		String str_local_addr = _local_addr.unparse_re();
		XID front_xid = handler->get_src_path().xid(handler->get_src_path().destination_node());
		String xid_string = front_xid.unparse();
		str_local_addr = str_local_addr + " " + xid_string; //Make source DAG _local_addr:SID
		handler->get_src_path().parse_re(str_local_addr);
	}


	if(handler->get_src_path().unparse_re().length() != 0) {
		//Recalculate source path
		XID	source_xid = handler->get_src_path().xid(handler->get_src_path().destination_node());
		String str_local_addr = _local_addr.unparse_re() + " " + source_xid.unparse(); //Make source DAG _local_addr:SID
		handler->get_src_path().parse(str_local_addr);
	}

//	if (DEBUG)
//		click_chatter("sent packet from %s, to %s\n", handler->src_path.unparse_re().c_str(), dest.c_str());

	WritablePacket *just_payload_part = WritablePacket::make(p_in->headroom() + 1, (const void*)x_sendto_msg->payload().c_str(), pktPayloadSize, p_in->tailroom());
	if (handler -> get_type() == XSOCKET_STREAM)
	{
		handler->usrsend(payload);
	} else if (handler -> get_type() == XSOCKET_DGRAM)
	{
		/* code */
	}

	// portToHandler.set(_sport, handler);
	rc = pktPayloadSize;
	x_sendto_msg->clear_payload();
	ReturnResult(_sport, xia_socket_msg, rc, ec);
}

void XTRANSPORT::Xrecv(unsigned short _sport, XSocketMsg *xia_socket_msg)
{
	XGenericTransport *handler = portToHandler.get(_sport);
	handler->read_from_recv_buf(xia_socket_msg);

	if (xia_socket_msg->x_recv().bytes_returned() > 0) {
		// Return response to API
		ReturnResult(_sport, xia_socket_msg, xia_socket_msg->x_recv().bytes_returned());
	} else if (!xia_socket_msg->blocking()) {
		// we're not blocking and there's no data, so let API know immediately
		handler->set_recv_pending(false);
		ReturnResult(_sport, xia_socket_msg, -1, EWOULDBLOCK);

	} else {
		// rather than returning a response, wait until we get data
		handler->set_recv_pending(true); // when we get data next, send straight to app

		// xia_socket_msg is saved on the stack; allocate a copy on the heap
		XSocketMsg *xsm_cpy = new XSocketMsg();
		xsm_cpy->CopyFrom(*xia_socket_msg);
		handler->set_pending_recv_msg(xsm_cpy);
	}
}

void XTRANSPORT::Xrecvfrom(unsigned short _sport, XSocketMsg *xia_socket_msg)
{
	XGenericTransport *handler = portToHandler.get(_sport);
	handler->read_from_recv_buf(xia_socket_msg);

	if (xia_socket_msg->x_recvfrom().bytes_returned() > 0) {
		// Return response to API
		ReturnResult(_sport, xia_socket_msg, xia_socket_msg->x_recvfrom().bytes_returned());

	} else if (!xia_socket_msg->blocking()) {

		// we're not blocking and there's no data, so let API know immediately
		ReturnResult(_sport, xia_socket_msg, -1, EWOULDBLOCK);

	} else {
		// rather than returning a response, wait until we get data
		handler->set_recv_pending(true); // when we get data next, send straight to app

		// xia_socket_msg is saved on the stack; allocate a copy on the heap
		XSocketMsg *xsm_cpy = new XSocketMsg();
		xsm_cpy->CopyFrom(*xia_socket_msg);
		handler->set_pending_recv_msg(xsm_cpy);
	}
}

void XTRANSPORT::XrequestChunk(unsigned short _sport, XSocketMsg *xia_socket_msg, WritablePacket *p_in)
{
	X_Requestchunk_Msg *x_requestchunk_msg = xia_socket_msg->mutable_x_requestchunk();

	String pktPayload(x_requestchunk_msg->payload().c_str(), x_requestchunk_msg->payload().size());
	int pktPayloadSize = pktPayload.length();

	// send CID-Requests

	for (int i = 0; i < x_requestchunk_msg->dag_size(); i++) {
		String dest = x_requestchunk_msg->dag(i).c_str();
		//printf("CID-Request for %s  (size=%d) \n", dest.c_str(), dag_size);
		//printf("\n\n (%s) hi 3 \n\n", (_local_addr.unparse()).c_str());
		XIAPath dst_path;
		dst_path.parse(dest);

		//Find DAG info for this DGRAM
		sock *sk = portToSock.get(_sport);

		if(!sk) {
			//No local SID bound yet, so bind one
			sk = new sock();
		}

		if (sk->initialized == false) {
			sk->initialized = true;
			sk->full_src_dag = true;
			sk->port = _sport;
			String str_local_addr = _local_addr.unparse_re();

			char xid_string[50];
			random_xid("SID", xid_string);
			str_local_addr = str_local_addr + " " + xid_string; //Make source DAG _local_addr:SID

			sk->src_path.parse_re(str_local_addr);

			sk->last = LAST_NODE_DEFAULT;
			sk->hlim = hlim.get(_sport);

			XID	source_xid = sk->src_path.xid(sk->src_path.destination_node());

			XIDtoPort.set(source_xid, _sport); //Maybe change the mapping to XID->sock?
			addRoute(source_xid);

		}

		// Case of initial binding to only SID
		if(sk->full_src_dag == false) {
			sk->full_src_dag = true;
			String str_local_addr = _local_addr.unparse_re();
			XID front_xid = sk->src_path.xid(sk->src_path.destination_node());
			String xid_string = front_xid.unparse();
			str_local_addr = str_local_addr + " " + xid_string; //Make source DAG _local_addr:SID
			sk->src_path.parse_re(str_local_addr);
		}

		if(sk->src_path.unparse_re().length() != 0) {
			//Recalculate source path
			XID	source_xid = sk->src_path.xid(sk->src_path.destination_node());
			String str_local_addr = _local_addr.unparse_re() + " " + source_xid.unparse(); //Make source DAG _local_addr:SID
			sk->src_path.parse(str_local_addr);
		}

		portToSock.set(_sport, sk);

		sk = portToSock.get(_sport);

//		if (DEBUG)
//			click_chatter("sent packet to %s, from %s\n", dest.c_str(), sk->src_path.unparse_re().c_str());

		//Add XIA headers
		XIAHeaderEncap xiah;
		xiah.set_nxt(CLICK_XIA_NXT_CID);
		xiah.set_last(LAST_NODE_DEFAULT);
		xiah.set_hlim(hlim.get(_sport));
		xiah.set_dst_path(dst_path);
		xiah.set_src_path(sk->src_path);
		xiah.set_plen(pktPayloadSize);

		WritablePacket *just_payload_part = WritablePacket::make(p_in->headroom() + 1, (const void*)x_requestchunk_msg->payload().c_str(), pktPayloadSize, p_in->tailroom());

		WritablePacket *p = NULL;

		//Add Content header
		ContentHeaderEncap *chdr = ContentHeaderEncap::MakeRequestHeader();
		p = chdr->encap(just_payload_part);
		p = xiah.encap(p, true);
		delete chdr;

		XID	source_sid = sk->src_path.xid(sk->src_path.destination_node());
		XID	destination_cid = dst_path.xid(dst_path.destination_node());

		XIDpair xid_pair;
		xid_pair.set_src(source_sid);
		xid_pair.set_dst(destination_cid);

		// Map the src & dst XID pair to source port
		XIDpairToPort.set(xid_pair, _sport);

		// Store the packet into buffer
		WritablePacket *copy_req_pkt = copy_cid_req_packet(p, sk);
		sk->XIDtoCIDreqPkt.set(destination_cid, copy_req_pkt);

		// Set the status of CID request
		sk->XIDtoStatus.set(destination_cid, WAITING_FOR_CHUNK);

		// Set the status of ReadCID reqeust
		sk->XIDtoReadReq.set(destination_cid, false);

		// Set timer
		Timestamp cid_req_expiry  = Timestamp::now() + Timestamp::make_msec(_ackdelay_ms);
		sk->XIDtoExpiryTime.set(destination_cid, cid_req_expiry);
		sk->XIDtoTimerOn.set(destination_cid, true);

		if (! _timer.scheduled() || _timer.expiry() >= cid_req_expiry )
			_timer.reschedule_at(cid_req_expiry);

		portToSock.set(_sport, sk);

		output(NETWORK_PORT).push(p);
	}

	ReturnResult(_sport, xia_socket_msg); // TODO: Error codes?
}

void XTRANSPORT::XgetChunkStatus(unsigned short _sport, XSocketMsg *xia_socket_msg)
{
	X_Getchunkstatus_Msg *x_getchunkstatus_msg = xia_socket_msg->mutable_x_getchunkstatus();

	int numCids = x_getchunkstatus_msg->dag_size();
	String pktPayload(x_getchunkstatus_msg->payload().c_str(), x_getchunkstatus_msg->payload().size());

	// send CID-Requests
	for (int i = 0; i < numCids; i++) {
		String dest = x_getchunkstatus_msg->dag(i).c_str();
		//printf("CID-Request for %s  (size=%d) \n", dest.c_str(), dag_size);
		//printf("\n\n (%s) hi 3 \n\n", (_local_addr.unparse()).c_str());
		XIAPath dst_path;
		dst_path.parse(dest);

		//Find DAG info for this DGRAM
		sock *sk = portToSock.get(_sport);

		XID	destination_cid = dst_path.xid(dst_path.destination_node());

		// Check the status of CID request
		HashTable<XID, int>::iterator it;
		it = sk->XIDtoStatus.find(destination_cid);

		if(it != sk->XIDtoStatus.end()) {
			// There is an entry
			int status = it->second;

			if(status == WAITING_FOR_CHUNK) {
				x_getchunkstatus_msg->add_status("WAITING");

			} else if(status == READY_TO_READ) {
				x_getchunkstatus_msg->add_status("READY");

			} else if(status == INVALID_HASH) {
				x_getchunkstatus_msg->add_status("INVALID_HASH");

			} else if(status == REQUEST_FAILED) {
				x_getchunkstatus_msg->add_status("FAILED");
			}

		} else {
			// Status query for the CID that was not requested...
			x_getchunkstatus_msg->add_status("FAILED");
		}
	}

	// Send back the report

	const char *buf = "CID request status response";
	x_getchunkstatus_msg->set_payload((const char*)buf, strlen(buf) + 1);

	ReturnResult(_sport, xia_socket_msg); // TODO: Error codes?
}

void XTRANSPORT::XreadChunk(unsigned short _sport, XSocketMsg *xia_socket_msg)
{
	X_Readchunk_Msg *x_readchunk_msg = xia_socket_msg->mutable_x_readchunk();

	String dest = x_readchunk_msg->dag().c_str();
	WritablePacket *copy;
	//printf("CID-Request for %s  (size=%d) \n", dest.c_str(), dag_size);
	//printf("\n\n (%s) hi 3 \n\n", (_local_addr.unparse()).c_str());
	XIAPath dst_path;
	dst_path.parse(dest);

	//Find DAG info for this DGRAM
	sock *sk = portToSock.get(_sport);

	XID	destination_cid = dst_path.xid(dst_path.destination_node());

	// Update the status of ReadCID reqeust
	sk->XIDtoReadReq.set(destination_cid, true);
	portToSock.set(_sport, sk);

	// Check the status of CID request
	HashTable<XID, int>::iterator it;
	it = sk->XIDtoStatus.find(destination_cid);

	if(it != sk->XIDtoStatus.end()) {
		// There is an entry
		int status = it->second;

		if (status != READY_TO_READ  &&
			status != INVALID_HASH) {
			// Do nothing

		} else {
			// Send the buffered pkt to upper layer

			sk->XIDtoReadReq.set(destination_cid, false);
			portToSock.set(_sport, sk);

			HashTable<XID, WritablePacket*>::iterator it2;
			it2 = sk->XIDtoCIDresponsePkt.find(destination_cid);
			copy = copy_cid_response_packet(it2->second, sk);

			XIAHeader xiah(copy->xia_header());

			//Unparse dag info
			String src_path = xiah.src_path().unparse();

			X_Readchunk_Msg *x_readchunk_msg = xia_socket_msg->mutable_x_readchunk();
			x_readchunk_msg->set_dag(src_path.c_str());
			x_readchunk_msg->set_payload((const char *)xiah.payload(), xiah.plen());

			//printf("FROM CACHE. data length = %d  \n", str.length());
//			if (DEBUG)
//				click_chatter("Sent packet to socket: sport %d dport %d", _sport, _sport);

			it2->second->kill();
			sk->XIDtoCIDresponsePkt.erase(it2);

			portToSock.set(_sport, sk);
		}
	}

	ReturnResult(_sport, xia_socket_msg); // TODO: Error codes?
}

void XTRANSPORT::XremoveChunk(unsigned short _sport, XSocketMsg *xia_socket_msg)
{
	X_Removechunk_Msg *x_rmchunk_msg = xia_socket_msg->mutable_x_removechunk();

	int32_t contextID = x_rmchunk_msg->contextid();
	String src(x_rmchunk_msg->cid().c_str(), x_rmchunk_msg->cid().size());
	//append local address before CID
	String str_local_addr = _local_addr.unparse_re();
	str_local_addr = "RE " + str_local_addr + " CID:" + src;
	XIAPath src_path;
	src_path.parse(str_local_addr);

	//Add XIA headers
	XIAHeaderEncap xiah;
	xiah.set_last(LAST_NODE_DEFAULT);
	xiah.set_hlim(HLIM_DEFAULT);
	xiah.set_dst_path(_local_addr);
	xiah.set_src_path(src_path);
	xiah.set_nxt(CLICK_XIA_NXT_CID);

	WritablePacket *just_payload_part = WritablePacket::make(256, (const void*)NULL, 0, 0);

	WritablePacket *p = NULL;
	ContentHeaderEncap  contenth(0, 0, 0, 0, ContentHeader::OP_LOCAL_REMOVECID, contextID);
	p = contenth.encap(just_payload_part);
	p = xiah.encap(p, true);

	if (DEBUG) {
		click_chatter("sent remove cid packet to cache");
	}
	output(CACHE_PORT).push(p);

	X_Removechunk_Msg *_msg = xia_socket_msg->mutable_x_removechunk();
	_msg->set_contextid(contextID);
	_msg->set_cid(src.c_str());
	_msg->set_status(0);

	ReturnResult(_sport, xia_socket_msg); // TODO: Error codes?
}

void XTRANSPORT::XputChunk(unsigned short _sport, XSocketMsg *xia_socket_msg)
{
	X_Putchunk_Msg *x_putchunk_msg = xia_socket_msg->mutable_x_putchunk();
//			int hasCID = x_putchunk_msg->hascid();
	int32_t contextID = x_putchunk_msg->contextid();
	int32_t ttl = x_putchunk_msg->ttl();
	int32_t cacheSize = x_putchunk_msg->cachesize();
	int32_t cachePolicy = x_putchunk_msg->cachepolicy();

	String pktPayload(x_putchunk_msg->payload().c_str(), x_putchunk_msg->payload().size());
	String src;

	/* Computes SHA1 Hash if user does not supply it */
	char hexBuf[3];
	int i = 0;
	SHA1_ctx sha_ctx;
	unsigned char digest[HASH_KEYSIZE];
	SHA1_init(&sha_ctx);
	SHA1_update(&sha_ctx, (unsigned char *)pktPayload.c_str() , pktPayload.length() );
	SHA1_final(digest, &sha_ctx);
	for(i = 0; i < HASH_KEYSIZE; i++) {
		sprintf(hexBuf, "%02x", digest[i]);
		src.append(const_cast<char *>(hexBuf), 2);
	}

	if(DEBUG) {
		click_chatter("ctxID=%d, length=%d, ttl=%d cid=%s\n",
					  contextID, x_putchunk_msg->payload().size(), ttl, src.c_str());
	}

	//append local address before CID
	String str_local_addr = _local_addr.unparse_re();
	str_local_addr = "RE " + str_local_addr + " CID:" + src;
	XIAPath src_path;
	src_path.parse(str_local_addr);

	if(DEBUG) {
		click_chatter("DAG: %s\n", str_local_addr.c_str());
	}

	/*TODO: The destination dag of the incoming packet is local_addr:XID
	 * Thus the cache thinks it is destined for local_addr and delivers to socket
	 * This must be ignored. Options
	 * 1. Use an invalid SID
	 * 2. The cache should only store the CID responses and not forward them to
	 *	local_addr when the source and the destination HIDs are the same.
	 * 3. Use the socket SID on which putCID was issued. This will
	 *	result in a reply going to the same socket on which the putCID was issued.
	 *	Use the response to return 1 to the putCID call to indicate success.
	 *	Need to add sk/ephemeral SID generation for this to work.
	 * 4. Special OPCODE in content extension header and treat it specially in content module (done below)
	 */

	//Add XIA headers
	XIAHeaderEncap xiah;
	xiah.set_last(LAST_NODE_DEFAULT);
	xiah.set_hlim(hlim.get(_sport));
	xiah.set_dst_path(_local_addr);
	xiah.set_src_path(src_path);
	xiah.set_nxt(CLICK_XIA_NXT_CID);

	//Might need to remove more if another header is required (eg some control/DAG info)

	WritablePacket *just_payload_part = WritablePacket::make(256, (const void*)pktPayload.c_str(), pktPayload.length(), 0);

	WritablePacket *p = NULL;
	int chunkSize = pktPayload.length();
	ContentHeaderEncap  contenth(0, 0, pktPayload.length(), chunkSize, ContentHeader::OP_LOCAL_PUTCID,
								 contextID, ttl, cacheSize, cachePolicy);
	p = contenth.encap(just_payload_part);
	p = xiah.encap(p, true);

	if (DEBUG)
		click_chatter("sent packet to cache");
	output(CACHE_PORT).push(p);

	// TODO: It looks like we were returning the chunk data with the result before. Any reason?
	ReturnResult(_sport, xia_socket_msg); // TODO: Error codes?
}

CLICK_ENDDECLS

EXPORT_ELEMENT(XTRANSPORT)
EXPORT_ELEMENT(XGenericTransport)
ELEMENT_REQUIRES(userlevel)
ELEMENT_REQUIRES(XIAContentModule)
ELEMENT_MT_SAFE(XTRANSPORT)
