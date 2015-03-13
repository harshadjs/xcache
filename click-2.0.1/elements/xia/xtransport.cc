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
    ConnIterator i = conn_handlers.begin(); 
    TCPConnection *con; 

    if (t == _fast_ticks) {
		for (; i; i++) {
			if (i.get_type() == XSOCKET_STREAM)
			{
				con = dynamic_cast<TCPConnection *>(i->second);
				con->fasttimo(); 
			}
		}
		_fast_ticks->reschedule_after_msec(TCP_FAST_TICK_MS);
    } else if (t == _slow_ticks) {
		for (; i; i++) {
			if (i.get_type() == XSOCKET_STREAM)
			{
			con = dynamic_cast<TCPConnection *>(i->second);
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

void
XTRANSPORT::run_timer_fake(Timer *timer)
{
//	pthread_mutex_lock(&_lock);

	assert(timer == &_timer);

	Timestamp now = Timestamp::now();
	Timestamp earlist_pending_expiry = now;

	WritablePacket *copy;

	bool tear_down;

	for (HashTable<unsigned short, TCPConnection*>::iterator iter = portToSock.begin(); iter != portToSock.end(); ++iter ) {
		unsigned short _sport = iter->first;
		TCPConnection *tcp_conn = portToSock.get(_sport);
		tear_down = false;

		// reset the concurrent poll flag so we know we can return a result to the next poll request
		tcp_conn->did_poll = false;

		// check if pending
		if (tcp_conn->timer_on == true) {
			// check if synack waiting
			if (tcp_conn->synack_waiting == true && tcp_conn->expiry <= now ) {
				//click_chatter("Timer: synack waiting\n");

				if (tcp_conn->num_connect_tries <= MAX_CONNECT_TRIES) {

					//click_chatter("Timer: SYN RETRANSMIT! \n");
					copy = copy_packet(tcp_conn->syn_pkt, tcp_conn);
					// retransmit syn
					XIAHeader xiah(copy);
					// printf("Timer: (%s) send=%s  len=%d \n\n", (_local_addr.unparse()).c_str(), (char *)xiah.payload(), xiah.plen());
					output(NETWORK_PORT).push(copy);

					tcp_conn->timer_on = true;
					tcp_conn->synack_waiting = true;
					tcp_conn->expiry = now + Timestamp::make_msec(_ackdelay_ms);
					tcp_conn->num_connect_tries++;

				} else {
					// Stop sending the connection request & Report the failure to the application

					tcp_conn->timer_on = false;
					tcp_conn->synack_waiting = false;

					// Notify API that the connection failed
					xia::XSocketMsg xsm;
					xsm.set_type(xia::XCONNECT);
					xsm.set_sequence(0); // TODO: what should This be?
					xia::X_Connect_Msg *connect_msg = xsm.mutable_x_connect();
					connect_msg->set_status(xia::X_Connect_Msg::XFAILED);
					ReturnResult(_sport, &xsm);

					if (tcp_conn->polling) {
						printf("checking poll event for %d from timer\n", _sport);
						ProcessPollEvent(_sport, POLLHUP);
					}

				}

			} else if (tcp_conn->dataack_waiting == true && tcp_conn->expiry <= now ) {

				// adding check to see if anything was retransmitted. We can get in here with
				// no packets in the tcp_conn->send_bufer array waiting to go and will stay here forever
				bool retransmit_sent = false;

				if (tcp_conn->num_retransmit_tries < MAX_RETRANSMIT_TRIES) {

				//click_chatter("Timer: DATA RETRANSMIT at from (%s) from_port=%d send_base=%d next_seq=%d \n\n", (_local_addr.unparse()).c_str(), _sport, tcp_conn->send_base, tcp_conn->next_send_seqnum );

					// retransmit data
					for (unsigned int i = tcp_conn->send_base; i < tcp_conn->next_send_seqnum; i++) {
						if (tcp_conn->send_buffer[i % tcp_conn->send_buffer_size] != NULL) {
							copy = copy_packet(tcp_conn->send_buffer[i % tcp_conn->send_buffer_size], tcp_conn);
							XIAHeader xiah(copy);
							//printf("Timer: (%s) send=%s  len=%d \n\n", (_local_addr.unparse()).c_str(), (char *)xiah.payload(), xiah.plen());
							//printf("pusing the retransmit pkt\n");
							output(NETWORK_PORT).push(copy);
							retransmit_sent = true;
						}
					}
				} else {
					//printf("retransmit counter exceeded\n");
					// FIXME what cleanup should happen here?
					// should we do a NAK?
				}

				if (retransmit_sent) {
					//click_chatter("resetting retransmit timer for %d\n", _sport);
					tcp_conn->timer_on = true;
					tcp_conn->dataack_waiting = true;
					tcp_conn-> num_retransmit_tries++;
					tcp_conn->expiry = now + Timestamp::make_msec(_ackdelay_ms);
				} else {
					//click_chatter("terminating retransmit timer for %d\n", _sport);
					tcp_conn->timer_on = false;
					tcp_conn->dataack_waiting = false;
					tcp_conn->num_retransmit_tries = 0;
				}

			} else if (tcp_conn->teardown_waiting == true && tcp_conn->teardown_expiry <= now) {
				tear_down = true;
				tcp_conn->timer_on = false;
				portToActive.set(_sport, false);

				//XID source_xid = portToSock.get(_sport).xid;

				// this check for -1 prevents a segfault cause by bad XIDs
				// it may happen in other cases, but opening a XSOCK_STREAM socket, calling
				// XreadLocalHostAddr and then closing the socket without doing anything else will
				// cause the problem
				// TODO: make sure that -1 is the only condition that will cause us to get a bad XID
				if (tcp_conn->src_path.destination_node() != -1) {
					XID source_xid = tcp_conn->src_path.xid(tcp_conn->src_path.destination_node());
					if (!tcp_conn->isAcceptSocket) {

						//click_chatter("deleting route %s from port %d\n", source_xid.unparse().c_str(), _sport);
						delRoute(source_xid);
						XIDtoPort.erase(source_xid);
					}
				}

				delete tcp_conn;
				portToSock.erase(_sport);
				portToActive.erase(_sport);
				hlim.erase(_sport);

				nxt_xport.erase(_sport);
				xcmp_listeners.remove(_sport);
				for (int i = 0; i < tcp_conn->send_buffer_size; i++) {
					if (tcp_conn->send_buffer[i] != NULL) {
						tcp_conn->send_buffer[i]->kill();
						tcp_conn->send_buffer[i] = NULL;
					}
				}
			}
		}

		if (tear_down == false) {

			// find the (next) earlist expiry
			if (tcp_conn->timer_on == true && tcp_conn->expiry > now && ( tcp_conn->expiry < earlist_pending_expiry || earlist_pending_expiry == now ) ) {
				earlist_pending_expiry = tcp_conn->expiry;
			}
			if (tcp_conn->timer_on == true && tcp_conn->teardown_expiry > now && ( tcp_conn->teardown_expiry < earlist_pending_expiry || earlist_pending_expiry == now ) ) {
				earlist_pending_expiry = tcp_conn->teardown_expiry;
			}


			// check for CID request cases
			for (HashTable<XID, bool>::iterator it = tcp_conn->XIDtoTimerOn.begin(); it != tcp_conn->XIDtoTimerOn.end(); ++it ) {
				XID requested_cid = it->first;
				bool timer_on = it->second;

				HashTable<XID, Timestamp>::iterator it2;
				it2 = tcp_conn->XIDtoExpiryTime.find(requested_cid);
				Timestamp cid_req_expiry = it2->second;

				if (timer_on == true && cid_req_expiry <= now) {
					//printf("CID-REQ RETRANSMIT! \n");
					//retransmit cid-request
					HashTable<XID, WritablePacket*>::iterator it3;
					it3 = tcp_conn->XIDtoCIDreqPkt.find(requested_cid);
					copy = copy_cid_req_packet(it3->second, tcp_conn);
					XIAHeader xiah(copy);
					//printf("\n\n (%s) send=%s  len=%d \n\n", (_local_addr.unparse()).c_str(), (char *)xiah.payload(), xiah.plen());
					output(NETWORK_PORT).push(copy);

					cid_req_expiry  = Timestamp::now() + Timestamp::make_msec(_ackdelay_ms);
					tcp_conn->XIDtoExpiryTime.set(requested_cid, cid_req_expiry);
					tcp_conn->XIDtoTimerOn.set(requested_cid, true);
				}

				if (timer_on == true && cid_req_expiry > now && ( cid_req_expiry < earlist_pending_expiry || earlist_pending_expiry == now ) ) {
					earlist_pending_expiry = cid_req_expiry;
				}
			}

			portToSock.set(_sport, tcp_conn);
		}
	}

//	pthread_mutex_unlock(&_lock);
}

void XTRANSPORT::copy_common(TCPConnection *tcp_conn, XIAHeader &xiahdr, XIAHeaderEncap &xiah) {

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
XTRANSPORT::copy_packet(Packet *p, TCPConnection *tcp_conn) {

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
XTRANSPORT::copy_cid_req_packet(Packet *p, TCPConnection *tcp_conn) {

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
XTRANSPORT::copy_cid_response_packet(Packet *p, TCPConnection *tcp_conn) {

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

/**
* @brief Calculates a connection's loacal receive window.
*
* recv_window = recv_buffer_size - (next_seqnum - base)
*
* @param tcp_conn
*
* @return The receive window.
*/
uint32_t XTRANSPORT::calc_recv_window(TCPConnection *tcp_conn) {
	return tcp_conn->recv_buffer_size - (tcp_conn->next_recv_seqnum - tcp_conn->recv_base);
}

/**
* @brief Checks whether or not a received packet can be buffered.
*
* Checks if we have room to buffer the received packet; that is, is the packet's
* sequence number within our recieve window? (Or, in the case of a DGRAM socket,
* simply checks if there is an unused slot at the end of the recv buffer.)
*
* @param p
* @param tcp_conn
*
* @return true if packet can be buffered, false otherwise
*/
// bool XTRANSPORT::should_buffer_received_packet(WritablePacket *p, TCPConnection *tcp_conn) {

// //printf("<<<< should_buffer_received_packet\n");

// 	if (tcp_conn->sock_type == XSOCKET_STREAM) {
// 		// check if received_seqnum is within our current recv window
// 		// TODO: if we switch to a byte-based, buf size, this needs to change
// 		TransportHeader thdr(p);
// 		int received_seqnum = thdr.seq_num();
// 		if (received_seqnum >= tcp_conn->next_recv_seqnum &&
// 			received_seqnum < tcp_conn->next_recv_seqnum + tcp_conn->recv_buffer_size) {
// 			return true;
// 		}
// 	} else if (tcp_conn->sock_type == XSOCKET_DGRAM) {

// //printf("    tcp_conn->recv_buffer_size: %u\n    tcp_conn->dgram_buffer_start: %u\n    tcp_conn->dgram_buffer_end: %u\n\n", tcp_conn->recv_buffer_size, tcp_conn->dgram_buffer_start, tcp_conn->dgram_buffer_end);

// 		//if ( (tcp_conn->dgram_buffer_end + 1) % tcp_conn->recv_buffer_size != tcp_conn->dgram_buffer_start) {
// 		if (tcp_conn->recv_buffer_count < tcp_conn->recv_buffer_size) {
// //printf("    return: TRUE\n");
// 			return true;
// 		}
// 	}
// //printf("    return: FALSE\n");
// 	return false;
// }

/**
* @brief Adds a packet to the connection's receive buffer.
*
* Stores the supplied packet pointer, p, in a slot depending on TCPConnection type:
*
*   STREAM: index = seqnum % bufsize.
*   DGRAM:  index = (end + 1) % bufsize
*
* @param p
* @param tcp_conn
*/
// void XTRANSPORT::add_packet_to_recv_buf(WritablePacket *p, TCPConnection *tcp_conn) {

// 	int index = -1;
// 	if (tcp_conn->sock_type == XSOCKET_STREAM) {
// 		TransportHeader thdr(p);
// 		int received_seqnum = thdr.seq_num();
// 		index = received_seqnum % tcp_conn->recv_buffer_size;
// //printf("    port=%u adding packet to index %d\n", tcp_conn->port, index);
// 	} else if (tcp_conn->sock_type == XSOCKET_DGRAM) {
// 		index = (tcp_conn->dgram_buffer_end + 1) % tcp_conn->recv_buffer_size;
// 		tcp_conn->dgram_buffer_end = index;
// 		tcp_conn->recv_buffer_count++;
// 	}

// 	WritablePacket *p_cpy = p->clone()->uniqueify();
// 	tcp_conn->recv_buffer[index] = p_cpy;
// }

/**
* @brief check to see if the app is waiting for this data; if so, return it now
*
* @param tcp_conn
*/
void XTRANSPORT::check_for_and_handle_pending_recv(TCPConnection *tcp_conn) {
	if (tcp_conn->recv_pending) {
		int bytes_returned = read_from_recv_buf(tcp_conn->pending_recv_msg, tcp_conn);
		ReturnResult(tcp_conn->port, tcp_conn->pending_recv_msg, bytes_returned);

		tcp_conn->recv_pending = false;
		delete tcp_conn->pending_recv_msg;
		tcp_conn->pending_recv_msg = NULL;
	}
}

/**
* @brief Returns the next expected sequence number.
*
* Beginning with tcp_conn->recv_base, this function checks consecutive slots
* in the receive buffer and returns the first missing sequence number.
* (This function only applies to STREAM sockets.)
*
* @param tcp_conn
*/
// uint32_t XTRANSPORT::next_missing_seqnum(TCPConnection *tcp_conn) {

// 	uint32_t next_missing = tcp_conn->recv_base;
// 	for (uint32_t i = 0; i < tcp_conn->recv_buffer_size; i++) {

// 		// checking if we have the next consecutive packet
// 		uint32_t seqnum_to_check = tcp_conn->recv_base + i;
// 		uint32_t index_to_check = seqnum_to_check % tcp_conn->recv_buffer_size;

// 		next_missing = seqnum_to_check;

// 		if (tcp_conn->recv_buffer[index_to_check]) {
// 			TransportHeader thdr(tcp_conn->recv_buffer[index_to_check]);
// 			if (thdr.seq_num() != seqnum_to_check) {
// 				break; // found packet, but its seqnum isn't right, so break and return next_missing
// 			}
// 		} else {
// 			break; // no packet here, so break and return next_missing
// 		}
// 	}

// 	return next_missing;
// }


// void XTRANSPORT::resize_buffer(WritablePacket* buf[], int max, int type, uint32_t old_size, uint32_t new_size, int *dgram_start, int *dgram_end) {

// 	if (new_size < old_size) {
// 		click_chatter("WARNING: new buffer size is smaller than old size. Some data may be discarded.\n");
// 		old_size = new_size; // so we stop after moving as many packets as will fit in the new buffer
// 	}

// 	// General procedure: make a temporary buffer and copy pointers to their
// 	// new indices in the temp buffer. Then, rewrite the original buffer.
// 	WritablePacket *temp[max];
// 	memset(temp, 0, max);

// 	// Figure out the new index for each packet in buffer
// 	int new_index = -1;
// 	for (int i = 0; i < old_size; i++) {
// 		if (type == XSOCKET_STREAM) {
// 			TransportHeader thdr(buf[i]);
// 			new_index = thdr.seq_num() % new_size;
// 		} else if (type == XSOCKET_DGRAM) {
// 			new_index = (i + *dgram_start) % old_size;
// 		}
// 		temp[new_index] = buf[i];
// 	}

// 	// For DGRAM socket, reset start and end vars
// 	if (type == XSOCKET_DGRAM) {
// 		*dgram_start = 0;
// 		*dgram_end = (*dgram_start + *dgram_end) % old_size;
// 	}

// 	// Copy new locations from temp back to original buf
// 	memset(buf, 0, max);
// 	for (int i = 0; i < max; i++) {
// 		buf[i] = temp[i];
// 	}
// }

// void XTRANSPORT::resize_send_buffer(TCPConnection *tcp_conn, uint32_t new_size) {
// 	resize_buffer(tcp_conn->send_buffer, MAX_SEND_WIN_SIZE, tcp_conn->sock_type, tcp_conn->send_buffer_size, new_size, &(tcp_conn->dgram_buffer_start), &(tcp_conn->dgram_buffer_end));
// 	tcp_conn->send_buffer_size = new_size;
// }

// void XTRANSPORT::resize_recv_buffer(TCPConnection *tcp_conn, uint32_t new_size) {
// 	resize_buffer(tcp_conn->recv_buffer, MAX_RECV_WIN_SIZE, tcp_conn->sock_type, tcp_conn->recv_buffer_size, new_size, &(tcp_conn->dgram_buffer_start), &(tcp_conn->dgram_buffer_end));
// 	tcp_conn->recv_buffer_size = new_size;
// }

/**
* @brief Read received data from buffer.
*
* We'll use this same xia_socket_msg as the response to the API:
* 1) We fill in the data (from *only one* packet for DGRAM)
* 2) We fill in how many bytes we're returning
* 3) We fill in the sender's DAG (DGRAM only)
* 4) We clear out any buffered packets whose data we return to the app
*
* @param xia_socket_msg The Xrecv or Xrecvfrom message from the API
* @param tcp_conn The TCPConnection struct for this connection
*
* @return  The number of bytes read from the buffer.
*/
int XTRANSPORT::read_from_recv_buf(xia::XSocketMsg *xia_socket_msg, TCPConnection *tcp_conn) {

	if (tcp_conn->sock_type == XSOCKET_STREAM) {
//		printf("<<< read_from_recv_buf: port=%u, recv_base=%d, next_recv_seqnum=%d, recv_buf_size=%d\n", tcp_conn->port, tcp_conn->recv_base, tcp_conn->next_recv_seqnum, tcp_conn->recv_buffer_size);
		xia::X_Recv_Msg *x_recv_msg = xia_socket_msg->mutable_x_recv();
		int bytes_requested = x_recv_msg->bytes_requested();
		int bytes_returned = 0;
		char buf[1024*1024]; // TODO: pick a buf size
		memset(buf, 0, 1024*1024);
		for (int i = tcp_conn->recv_base; i < tcp_conn->next_recv_seqnum; i++) {

			if (bytes_returned >= bytes_requested) break;

			WritablePacket *p = tcp_conn->recv_buffer[i % tcp_conn->recv_buffer_size];
			XIAHeader xiah(p->xia_header());
			TransportHeader thdr(p);
			size_t data_size = xiah.plen() - thdr.hlen();

			memcpy((void*)(&buf[bytes_returned]), (const void*)thdr.payload(), data_size);
			bytes_returned += data_size;

			p->kill();
			tcp_conn->recv_buffer[i % tcp_conn->recv_buffer_size] = NULL;
			tcp_conn->recv_base++;
//			printf("    port %u grabbing index %d, seqnum %d\n", tcp_conn->port, i%tcp_conn->recv_buffer_size, i);
		}
		x_recv_msg->set_payload(buf, bytes_returned); // TODO: check this: need to turn buf into String first?
		x_recv_msg->set_bytes_returned(bytes_returned);

//		printf(">>> read_from_recv_buf: port=%u, recv_base=%d, next_recv_seqnum=%d, recv_buf_size=%d\n", tcp_conn->port, tcp_conn->recv_base, tcp_conn->next_recv_seqnum, tcp_conn->recv_buffer_size);
		return bytes_returned;

	} else if (tcp_conn->sock_type == XSOCKET_DGRAM) {
		xia::X_Recvfrom_Msg *x_recvfrom_msg = xia_socket_msg->mutable_x_recvfrom();
	
		// Get just the next packet in the recv buffer (we don't return data from more
		// than one packet in case the packets came from different senders). If no
		// packet is available, we indicate to the app that we returned 0 bytes.
		WritablePacket *p = tcp_conn->recv_buffer[tcp_conn->dgram_buffer_start];

		if (tcp_conn->recv_buffer_count > 0 && p) {
			XIAHeader xiah(p->xia_header());
			TransportHeader thdr(p);
			int data_size = xiah.plen() - thdr.hlen();

			String src_path = xiah.src_path().unparse();
			String payload((const char*)thdr.payload(), data_size);
			x_recvfrom_msg->set_payload(payload.c_str(), payload.length());
			x_recvfrom_msg->set_sender_dag(src_path.c_str());
			x_recvfrom_msg->set_bytes_returned(data_size);

			p->kill();
			tcp_conn->recv_buffer[tcp_conn->dgram_buffer_start] = NULL;
			tcp_conn->recv_buffer_count--;
			tcp_conn->dgram_buffer_start = (tcp_conn->dgram_buffer_start + 1) % tcp_conn->recv_buffer_size;
			return data_size;
		} else {
			x_recvfrom_msg->set_bytes_returned(0);
			return 0;
		}
	}

	return -1;
}


void XTRANSPORT::ProcessNetworkPacket(WritablePacket *p_in)
{

	XIAHeader xiah(p_in->xia_header());
	XIAPath dst_path = xiah.dst_path();
	XIAPath src_path = xiah.src_path();
	XID _destination_xid(xiah.hdr()->node[xiah.last()].xid);
	XID	_source_xid = src_path.xid(src_path.destination_node());
	TransportHeader thdr(p_in);

	if (xiah.nxt() == CLICK_XIA_NXT_XCMP) { // TODO:  Should these be put in recv buffer???

		String src_path = xiah.src_path().unparse();
		String header((const char*)xiah.hdr(), xiah.hdr_size());
		String payload((const char*)xiah.payload(), xiah.plen());
		String str = header + payload;

		xia::XSocketMsg xsm;
		xsm.set_type(xia::XRECV);
		xia::X_Recvfrom_Msg *x_recvfrom_msg = xsm.mutable_x_recvfrom();
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

	unsigned short _dport = 0;  
	unsigned short _sport = 0;
	if (thdr.type() == TransportHeader::XSOCK_STREAM) 
	{
		_dport = thdr.header() -> th_dport;
		_sport = thdr.header() -> th_sport;
	} else if (thdr.type() == TransportHeader::XSOCK_DGRAM) {
		_dport = thdr.header() -> uh_dport;
		_sport = thdr.header() -> uh_sport;
	}

	XIPFlowID flowid(_destination_xid, _dport, _source_xid, _sport);
	GenericConnHandler *handler = conn_handlers.get(flowid);
	if (handler == NULL && thdr.type() == TransportHeader::XSOCK_DGRAM)
	{
		p_in -> kill();
		return;
	} else if (handler == NULL && thdr.type() == TransportHeader::XSOCK_STREAM) {
		struct click_tcp *tcph = thdr.header();
		if (tcph->th_flags == TH_SYN)
		{
			TCPConnection tcp_conn(&this, flowid);
			conn_handlers[flowid] = &tcp_conn;
			tcp_conn -> push(p_in);
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
			rst_tcph.th_sport = tcph -> th_dport;
			rst_tcph.th_dport = tcph -> th_sport;
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
	unsigned short _dport = DST_PORT_ANNO(p_in);

//	if (DEBUG)
//      click_chatter("\nPush: Got packet from API sport:%d",ntohs(_sport));

	std::string p_buf;
	p_buf.assign((const char*)p_in->data(), (const char*)p_in->end_data());

	//protobuf message parsing
	xia::XSocketMsg xia_socket_msg;
	xia_socket_msg.ParseFromString(p_buf);

	switch(xia_socket_msg.type()) {
	case xia::XSOCKET:
		Xsocket(_sport, _dport, &xia_socket_msg);
		break;
	case xia::XSETSOCKOPT:
		Xsetsockopt(_sport, _dport, &xia_socket_msg);
		break;
	case xia::XGETSOCKOPT:
		Xgetsockopt(_sport, _dport, &xia_socket_msg);
		break;
	case xia::XBIND:
		Xbind(_sport, _dport, &xia_socket_msg);
		break;
	case xia::XCLOSE:
		Xclose(_sport, _dport, &xia_socket_msg);
		break;
	case xia::XCONNECT:
		Xconnect(_sport, _dport, &xia_socket_msg);
		break;
	case xia::XREADYTOACCEPT:
		XreadyToAccept(_sport, _dport, &xia_socket_msg);
		break;
	case xia::XACCEPT:
		Xaccept(_sport, _dport, &xia_socket_msg);
		break;
	case xia::XCHANGEAD:
		Xchangead(_sport, _dport, &xia_socket_msg);
		break;
	case xia::XREADLOCALHOSTADDR:
		Xreadlocalhostaddr(_sport, _dport, &xia_socket_msg);
		break;
	case xia::XUPDATENAMESERVERDAG:
		Xupdatenameserverdag(_sport, _dport, &xia_socket_msg);
		break;
	case xia::XREADNAMESERVERDAG:
		Xreadnameserverdag(_sport, _dport, &xia_socket_msg);
		break;
	case xia::XISDUALSTACKROUTER:
		Xisdualstackrouter(_sport, _dport, &xia_socket_msg);
		break;
    case xia::XSEND:
		Xsend(_sport, _dport, &xia_socket_msg, p_in);
		break;
	case xia::XSENDTO:
		Xsendto(_sport, _dport, &xia_socket_msg, p_in);
		break;
	case xia::XRECV:
		Xrecv(_sport, _dport, &xia_socket_msg);
		break;
	case xia::XRECVFROM:
		Xrecvfrom(_sport, _dport, &xia_socket_msg);
		break;
	case xia::XREQUESTCHUNK:
		XrequestChunk(_sport, _dport, &xia_socket_msg, p_in);
		break;
	case xia::XGETCHUNKSTATUS:
		XgetChunkStatus(_sport, _dport, &xia_socket_msg);
		break;
	case xia::XREADCHUNK:
		XreadChunk(_sport, _dport, &xia_socket_msg);
		break;
	case xia::XREMOVECHUNK:
		XremoveChunk(_sport, _dport, &xia_socket_msg);
		break;
	case xia::XPUTCHUNK:
		XputChunk(_sport, _dport, &xia_socket_msg);
		break;
	case xia::XGETPEERNAME:
		Xgetpeername(_sport, _dport, &xia_socket_msg);
		break;
	case xia::XGETSOCKNAME:
		Xgetsockname(_sport, _dport, &xia_socket_msg);
		break;
	case xia::XPOLL:
		Xpoll(_sport, _dport, &xia_socket_msg);
		break;
	default:
		click_chatter("\n\nERROR: API TRAFFIC !!!\n\n");
		break;
	}

	p_in->kill();
}

void XTRANSPORT::ReturnResult(int sport, xia::XSocketMsg *xia_socket_msg, int rc, int err)
{
//	click_chatter("sport=%d type=%d rc=%d err=%d\n", sport, type, rc, err);
	xia::X_Result_Msg *x_result = xia_socket_msg->mutable_x_result();
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
void XTRANSPORT::Xsocket(unsigned short _sport, xia::XSocketMsg *xia_socket_msg) {
	//Open socket.
	click_chatter("Xsocket: create socket %d\n", _sport);
	printf("Xsocket: create socket %d\n", _sport);

	xia::X_Socket_Msg *x_socket_msg = xia_socket_msg->mutable_x_socket();
	int sock_type = x_socket_msg->type();

	switch (socket_type) {
		case XSOCKET_STREAM:
		XIPFlowID flowid(NULL, NULL, _sport, 0);
		TCPConnection tcp_conn(this, &flowid);
		break;
		case XSOCKET_DGRAM:
		default:
		//TODO
		break;
	}


	hlim.set(_sport, HLIM_DEFAULT);
	nxt_xport.set(_sport, CLICK_XIA_NXT_TRN);

	// printf("XSOCKET: sport=%hu\n", _sport);

	// Return result to API
	ReturnResult(_sport, xia_socket_msg, 0);
}

/*
** Xsetsockopt API handler
*/
void XTRANSPORT::Xsetsockopt(unsigned short _sport, xia::XSocketMsg *xia_socket_msg) {

	// click_chatter("\nSet Socket Option\n");
	xia::X_Setsockopt_Msg *x_sso_msg = xia_socket_msg->mutable_x_setsockopt();

	switch (x_sso_msg->opt_type())
	{
	case XOPT_HLIM:
	{
		int hl = x_sso_msg->int_opt();

		hlim.set(_sport, hl);
		//click_chatter("sso:hlim:%d\n",hl);
	}
	break;

	case XOPT_NEXT_PROTO:
	{
		int nxt = x_sso_msg->int_opt();
		nxt_xport.set(_sport, nxt);
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

	ReturnResult(_sport, xia_socket_msg); // TODO: return code
}

/*
** Xgetsockopt API handler
*/
void XTRANSPORT::Xgetsockopt(unsigned short _sport, xia::XSocketMsg *xia_socket_msg) {
	// click_chatter("\nGet Socket Option\n");
	xia::X_Getsockopt_Msg *x_sso_msg = xia_socket_msg->mutable_x_getsockopt();

	// click_chatter("opt = %d\n", x_sso_msg->opt_type());
	switch (x_sso_msg->opt_type())
	{
	case XOPT_HLIM:
	{
		x_sso_msg->set_int_opt(hlim.get(_sport));
		//click_chatter("gso:hlim:%d\n", hlim.get(_sport));
	}
	break;

	case XOPT_NEXT_PROTO:
	{
		x_sso_msg->set_int_opt(nxt_xport.get(_sport));
	}
	break;

	default:
		// unsupported option
		break;
	}

	ReturnResult(_sport, xia_socket_msg); // TODO: return code
}

void XTRANSPORT::Xbind(unsigned short _sport, xia::XSocketMsg *xia_socket_msg) {

	int rc = 0, ec = 0;


	//Bind XID
	//click_chatter("\n\nOK: SOCKET BIND !!!\\n");
	//get source DAG from protobuf message

	xia::X_Bind_Msg *x_bind_msg = xia_socket_msg->mutable_x_bind();

	String sdag_string(x_bind_msg->sdag().c_str(), x_bind_msg->sdag().size());
	XIPFlowID flowid(NULL, NULL, _sport, 0);
	//String sdag_string((const char*)p_in->data(),(const char*)p_in->end_data());
//	if (DEBUG)
//		click_chatter("\nbind requested to %s, length=%d\n", sdag_string.c_str(), (int)p_in->length());

	//String str_local_addr=_local_addr.unparse();
	//str_local_addr=str_local_addr+" "+xid_string;//Make source DAG _local_addr:SID

	//Set the source DAG in sock
	TCPConnection *tcp_conn = (TCPConnection*)conn_handlers.get(flowid);
	if (tcp_conn->src_path().parse(sdag_string)) {
		tcp_conn->set_nxt(LAST_NODE_DEFAULT);
		tcp_conn->set_last(LAST_NODE_DEFAULT);
		tcp_conn->set_hlim(hlim.get(_sport));

		// tcp_conn->sdag = sdag_string;

		//Check if binding to full DAG or just to SID only
		Vector<XIAPath::handle_t> xids = tcp_conn->src_path().next_nodes( tcp_conn->src_path.source_node() );
		XID front_xid = tcp_conn->src_path().xid( xids[0] );
		struct click_xia_xid head_xid = front_xid.xid();
		uint32_t head_xid_type = head_xid.type;
		if(head_xid_type == _sid_type) {
			tcp_conn->set_full_src_dag(false);
		} else {
			tcp_conn->set_full_src_dag(true);
		}

		XID	source_xid = tcp_conn->src_path().xid(tcp_conn->src_path.destination_node());
		//XID xid(xid_string);
		//TODO: Add a check to see if XID is already being used

		// Map the source XID to source port (for now, for either type of tranports)
		
		addRoute(source_xid);
//		printf("Xbind, S2P %d, %p\n", _sport, tcp_conn);
		// portToSock.set(_sport, tcp_conn);
		conn_handlers.remove(flowid);
		flowid.set_saddr(source_xid);
		conn_handlers[flowid] = tcp_conn;
		//click_chatter("Bound");
		//click_chatter("set %d %d",_sport, __LINE__);

	} else {
		rc = -1;
		ec = EADDRNOTAVAIL;
	}
	
	ReturnResult(_sport, xia_socket_msg, rc, ec);
}

void XTRANSPORT::Xclose(unsigned short _sport, xia::XSocketMsg *xia_socket_msg)
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

	TCPConnection *tcp_conn = conn_handlers.get(_sport);
	tcp_conn->usrclosed();
	xcmp_listeners.remove(_sport);

	ReturnResult(_sport, xia_socket_msg);
}

void XTRANSPORT::Xconnect(unsigned short _sport, xia::XSocketMsg *xia_socket_msg)
{
	//click_chatter("Xconect: connecting %d\n", _sport);

	//isConnected=true;
	//String dest((const char*)p_in->data(),(const char*)p_in->end_data());
	//click_chatter("\nconnect to %s, length=%d\n",dest.c_str(),(int)p_in->length());

	xia::X_Connect_Msg *x_connect_msg = xia_socket_msg->mutable_x_connect();

	String dest(x_connect_msg->ddag().c_str());

	//String sdag_string((const char*)p_in->data(),(const char*)p_in->end_data());
	//click_chatter("\nconnect requested to %s, length=%d\n",dest.c_str(),(int)p_in->length());

	XIAPath dst_path;
	dst_path.parse(dest);

	sock *sk = portToSock.get(_sport);
	//click_chatter("connect %d %x",_sport, sk);

	if(!sk) {
		//click_chatter("Create DAGINFO connect %d %x",_sport, sk);
		//No local SID bound yet, so bind ephemeral one
		sk = new sock();
	} else {
		if (sk->synack_waiting) {
			// a connect is already in progress
			x_connect_msg->set_status(xia::X_Connect_Msg::XCONNECTING);
			ReturnResult(_sport, xia_socket_msg, -1, EALREADY);
		}
	}

	sk->dst_path = dst_path;
	sk->port = _sport;
	sk->isConnected = true;
	sk->initialized = true;
	sk->ddag = dest;
	sk->seq_num = 0;
	sk->ack_num = 0;
	sk->send_base = 0;
	sk->next_send_seqnum = 0;
	sk->next_recv_seqnum = 0;
	sk->num_connect_tries++; // number of xconnect tries (Xconnect will fail after MAX_CONNECT_TRIES trials)

	String str_local_addr = _local_addr.unparse_re();
	//String dagstr = sk->src_path.unparse_re();

	/* Use src_path set by Xbind() if exists */
	if(sk->sdag.length() == 0) {
		char xid_string[50];
		random_xid("SID", xid_string);

		str_local_addr = str_local_addr + " " + xid_string; //Make source DAG _local_addr:SID
		sk->src_path.parse_re(str_local_addr);
	}

	sk->nxt = LAST_NODE_DEFAULT;
	sk->last = LAST_NODE_DEFAULT;
	sk->hlim = hlim.get(_sport);

	XID source_xid = sk->src_path.xid(sk->src_path.destination_node());
	XID destination_xid = sk->dst_path.xid(sk->dst_path.destination_node());

	XIDpair xid_pair;
	xid_pair.set_src(source_xid);
	xid_pair.set_dst(destination_xid);

	// Map the src & dst XID pair to source port()
	//printf("Xconnect setting pair to port1 %d %s %s\n", _sport, source_xid.unparse().c_str(), destination_xid.unparse().c_str());

	XIDpairToPort.set(xid_pair, _sport);

	// Map the source XID to source port
	XIDtoPort.set(source_xid, _sport);
	addRoute(source_xid);

	// click_chatter("XCONNECT: set %d %x",_sport, sk);

	// Prepare SYN packet

	//Add XIA headers
	XIAHeaderEncap xiah;
	xiah.set_nxt(CLICK_XIA_NXT_TRN);
	xiah.set_last(LAST_NODE_DEFAULT);
	xiah.set_hlim(hlim.get(_sport));
	xiah.set_dst_path(dst_path);
	xiah.set_src_path(sk->src_path);

	//click_chatter("Sent packet to network");
	const char* dummy = "Connection_request";
	WritablePacket *just_payload_part = WritablePacket::make(256, dummy, strlen(dummy), 20);

	WritablePacket *p = NULL;

	TransportHeaderEncap *thdr = TransportHeaderEncap::MakeSYNHeader( 0, -1, 0, calc_recv_window(sk)); // #seq, #ack, length, recv_wind

	p = thdr->encap(just_payload_part);

	thdr->update();
	xiah.set_plen(strlen(dummy) + thdr->hlen()); // XIA payload = transport header + transport-layer data

	p = xiah.encap(p, false);

	delete thdr;

	// Set timer
	sk->timer_on = true;
	sk->synack_waiting = true;
	sk->expiry = Timestamp::now() + Timestamp::make_msec(_ackdelay_ms);

	if (! _timer.scheduled() || _timer.expiry() >= sk->expiry )
		_timer.reschedule_at(sk->expiry);

	// Store the syn packet for potential retransmission
	sk->syn_pkt = copy_packet(p, sk);

	portToSock.set(_sport, sk);
	XIAHeader xiah1(p);
	//String pld((char *)xiah1.payload(), xiah1.plen());
	// printf("XCONNECT: %d: %s\n", _sport, (_local_addr.unparse()).c_str());
	output(NETWORK_PORT).push(p);

	//sk=portToSock.get(_sport);
	//click_chatter("\nbound to %s\n",portToSock.get(_sport)->src_path.unparse().c_str());

	// We return EINPROGRESS no matter what. If we're in non-blocking mode, the
	// API will pass EINPROGRESS on to the app. If we're in blocking mode, the API
	// will wait until it gets another message from xtransport notifying it that
	// the other end responded and the connection has been established.
	x_connect_msg->set_status(xia::X_Connect_Msg::XCONNECTING);
	ReturnResult(_sport, xia_socket_msg, -1, EINPROGRESS);
}

void XTRANSPORT::XreadyToAccept(unsigned short _sport, xia::XSocketMsg *xia_socket_msg)
{
	// If there is already a pending connection, return true now
	// If not, add this request to the pendingAccept queue
	sock *sk = portToSock.get(_sport);

	if (!sk->pending_connection_buf.empty()) {
		ReturnResult(_sport, xia_socket_msg);
	} else {
		// xia_socket_msg is saved on the stack; allocate a copy on the heap
		xia::XSocketMsg *xsm_cpy = new xia::XSocketMsg();
		xsm_cpy->CopyFrom(*xia_socket_msg);
		sk->pendingAccepts.push(xsm_cpy);
	}
}

void XTRANSPORT::Xaccept(unsigned short _sport, xia::XSocketMsg *xia_socket_msg)
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
		//new_sk->pendingAccepts = new queue<xia::XSocketMsg*>();

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
		xia::X_Accept_Msg *x_accept_msg = xia_socket_msg->mutable_x_accept();
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

		xia::XSocketMsg xsm;
		xsm.set_type(xia::XPOLL);
		xia::X_Poll_Msg *msg = xsm.mutable_x_poll();
		
		xia::X_Poll_Msg::PollFD *pfd = msg->add_pfds();
		pfd->set_flags(flags_out);
		pfd->set_port(port);

		msg->set_nfds(1);

		// do I need to set other flags in the return struct?
		ReturnResult(pollport, &xsm, 1, 0);

		// found the socket, decrement the polling count for all the sockets in the poll instance
		for (HashTable<unsigned short, unsigned int>::iterator pit = pe.events.begin(); pit != pe.events.end(); pit++) {
			port = pit->first;

			sock *sk = portToSock.get(port);
			sk->polling--;
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

		sock *sk = portToSock.get(port);
		sk->polling--;
	}

	// get rid of this poll event
	poll_events.erase(it);
}


void XTRANSPORT::CreatePollEvent(unsigned short _sport, xia::X_Poll_Msg *msg)
{
	PollEvent pe;
	uint32_t nfds = msg->nfds();

	// printf("XPOLL Create:\nnfds:%d\n", nfds);

	for (int i = 0; i < nfds; i++) {
		const xia::X_Poll_Msg::PollFD& pfd = msg->pfds(i);

		int port = pfd.port();
		unsigned flags = pfd.flags();

		// ignore ports that are set to 0, or are negative
		if (port <= 0)
			continue;

		// add the socket to this poll event
		pe.events.set(port, flags);
		sock *sk = portToSock.get(port);

		// let the socket know a poll is enabled on it
		sk->polling++;
	}

	// register the poll event 
	poll_events.set(_sport, pe);
}


void XTRANSPORT::Xpoll(unsigned short _sport, xia::XSocketMsg *xia_socket_msg)
{
	xia::X_Poll_Msg *poll_in = xia_socket_msg->mutable_x_poll();

	if (poll_in->type() == xia::X_Poll_Msg::DOPOLL) {

		int actionable = 0;	
		xia::XSocketMsg msg_out;
		msg_out.set_type(xia::XPOLL);
		xia::X_Poll_Msg *poll_out = msg_out.mutable_x_poll();

		unsigned nfds = poll_in->nfds();

		// printf("XPOLL:\nnfds:%d\n", nfds);
		for (int i = 0; i < nfds; i++) {
			const xia::X_Poll_Msg::PollFD& pfd_in = poll_in->pfds(i);

			int port = pfd_in.port();
			unsigned flags = pfd_in.flags();
			// printf("port: %d, flags: %x\n", pfd_in.port(), pfd_in.flags());

			// skip over ignored ports
			if ( port <= 0) {
				// printf("skipping ignored port\n");
				continue;
			}

			sock *sk = portToSock.get(port);
			unsigned flags_out = 0;

			if (!sk) {
				// no socket state, we'll return an error right away
				// printf("No socket state found for %d\n", port);
				flags_out = POLLNVAL;
			
			} else {
				// is there any read data?
				if (flags & POLLIN) {
					if (sk->recv_pending) {
						// printf("read data avaialable on %d\n", port);
						flags_out |= POLLIN;
					}
				}

				if (flags & POLLOUT) {
					// see if the socket is writable
					// FIXME should we be looking for anything else (send window, etc...)
					if (sk->sock_type == SOCK_STREAM) {
						if (sk->isConnected) {
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
				xia::X_Poll_Msg::PollFD *pfd_out = poll_out->add_pfds();
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


void XTRANSPORT::Xchangead(unsigned short _sport, xia::XSocketMsg *xia_socket_msg)
{
	UNUSED(_sport);

	xia::X_Changead_Msg *x_changead_msg = xia_socket_msg->mutable_x_changead();
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

void XTRANSPORT::Xreadlocalhostaddr(unsigned short _sport, xia::XSocketMsg *xia_socket_msg)
{
	// read the localhost AD and HID
	String local_addr = _local_addr.unparse();
	size_t AD_found_start = local_addr.find_left("AD:");
	size_t AD_found_end = local_addr.find_left(" ", AD_found_start);
	String AD_str = local_addr.substring(AD_found_start, AD_found_end - AD_found_start);
	String HID_str = _local_hid.unparse();
	String IP4ID_str = _local_4id.unparse();
	// return a packet containing localhost AD and HID
	xia::X_ReadLocalHostAddr_Msg *_msg = xia_socket_msg->mutable_x_readlocalhostaddr();
	_msg->set_ad(AD_str.c_str());
	_msg->set_hid(HID_str.c_str());
	_msg->set_ip4id(IP4ID_str.c_str());

	ReturnResult(_sport, xia_socket_msg);
}

void XTRANSPORT::Xupdatenameserverdag(unsigned short _sport, xia::XSocketMsg *xia_socket_msg)
{
	UNUSED(_sport);

	xia::X_Updatenameserverdag_Msg *x_updatenameserverdag_msg = xia_socket_msg->mutable_x_updatenameserverdag();
	String ns_dag(x_updatenameserverdag_msg->dag().c_str());
	//click_chatter("new nameserver address is - %s", ns_dag.c_str());
	_nameserver_addr.parse(ns_dag);

	ReturnResult(_sport, xia_socket_msg);
}

void XTRANSPORT::Xreadnameserverdag(unsigned short _sport, xia::XSocketMsg *xia_socket_msg)
{
	// read the nameserver DAG
	String ns_addr = _nameserver_addr.unparse();

	// return a packet containing the nameserver DAG
	xia::X_ReadNameServerDag_Msg *_msg = xia_socket_msg->mutable_x_readnameserverdag();
	_msg->set_dag(ns_addr.c_str());

	ReturnResult(_sport, xia_socket_msg);
}

void XTRANSPORT::Xisdualstackrouter(unsigned short _sport, xia::XSocketMsg *xia_socket_msg)
{
	// return a packet indicating whether this node is an XIA-IPv4 dual-stack router
	xia::X_IsDualStackRouter_Msg *_msg = xia_socket_msg->mutable_x_isdualstackrouter();
	_msg->set_flag(_is_dual_stack_router);

	ReturnResult(_sport, xia_socket_msg);
}

void XTRANSPORT::Xgetpeername(unsigned short _sport, xia::XSocketMsg *xia_socket_msg)
{
	sock *sk = portToSock.get(_sport);

	xia::X_GetPeername_Msg *_msg = xia_socket_msg->mutable_x_getpeername();
	_msg->set_dag(sk->dst_path.unparse().c_str());

	ReturnResult(_sport, xia_socket_msg);
}


void XTRANSPORT::Xgetsockname(unsigned short _sport, xia::XSocketMsg *xia_socket_msg)
{
	sock *sk = portToSock.get(_sport);

	xia::X_GetSockname_Msg *_msg = xia_socket_msg->mutable_x_getsockname();
	_msg->set_dag(sk->src_path.unparse().c_str());

	ReturnResult(_sport, xia_socket_msg);
}


void XTRANSPORT::Xsend(unsigned short _sport, xia::XSocketMsg *xia_socket_msg, WritablePacket *p_in)
{
	int rc = 0, ec = 0;
	//click_chatter("Xsend on %d\n", _sport);

	xia::X_Send_Msg *x_send_msg = xia_socket_msg->mutable_x_send();
	int pktPayloadSize = x_send_msg->payload().size();

	//click_chatter("pkt %s port %d", pktPayload.c_str(), _sport);
	//printf("XSEND: %d bytes from (%d)\n", pktPayloadSize, _sport);

	//Find socket state
	sock *sk = portToSock.get(_sport);

	// Make sure the socket state isn't null
	if (rc == 0 && !sk) {
		rc = -1;
		ec = EBADF; // FIXME: is this the right error?
	}

	// Make sure socket is connected
	if (rc == 0 && !sk->isConnected) {
		rc = -1;
		ec = ENOTCONN;
	}

	// FIXME: in blocking mode, send should block until buffer space is available.
	int numUnACKedSentPackets = sk->next_send_seqnum - sk->send_base;
	if (rc == 0 && 
		numUnACKedSentPackets >= sk->send_buffer_size &&  // make sure we have space in send buf
		numUnACKedSentPackets >= sk->remote_recv_window) { // and receiver has space in recv buf

//		if (numUnACKedSentPackets >= sk->send_buffer_size)
//			printf("Not sending -- out of send buf space\n");
//		else if (numUnACKedSentPackets >= sk->remote_recv_window)
//			printf("Not sending -- out of recv buf space\n");

		rc = 0; // -1;  // set to 0 for now until blocking behavior is fixed
		ec = EAGAIN;
	}

	// If everything is OK so far, try sending
	if (rc == 0) {
		rc = pktPayloadSize;

		//Recalculate source path
		XID	source_xid = sk->src_path.xid(sk->src_path.destination_node());
		String str_local_addr = _local_addr.unparse_re() + " " + source_xid.unparse();
		//Make source DAG _local_addr:SID
		String dagstr = sk->src_path.unparse_re();

		//Client Mobility...
		if (dagstr.length() != 0 && dagstr != str_local_addr) {
			//Moved!
			// 1. Update 'sk->src_path'
			sk->src_path.parse_re(str_local_addr);
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

		//Add XIA headers
		XIAHeaderEncap xiah;
		xiah.set_nxt(CLICK_XIA_NXT_TRN);
		xiah.set_last(LAST_NODE_DEFAULT);
		xiah.set_hlim(hlim.get(_sport));
		xiah.set_dst_path(sk->dst_path);
		xiah.set_src_path(sk->src_path);
		xiah.set_plen(pktPayloadSize);

//		if (DEBUG)
//			click_chatter("XSEND: (%d) sent packet to %s, from %s\n", _sport, sk->dst_path.unparse_re().c_str(), sk->src_path.unparse_re().c_str());

		WritablePacket *just_payload_part = WritablePacket::make(p_in->headroom() + 1, (const void*)x_send_msg->payload().c_str(), pktPayloadSize, p_in->tailroom());

		WritablePacket *p = NULL;

		//Add XIA Transport headers
		TransportHeaderEncap *thdr = TransportHeaderEncap::MakeDATAHeader(sk->next_send_seqnum, sk->ack_num, 0, calc_recv_window(sk) ); // #seq, #ack, length, recv_wind
		p = thdr->encap(just_payload_part);

		thdr->update();
		xiah.set_plen(pktPayloadSize + thdr->hlen()); // XIA payload = transport header + transport-layer data

		p = xiah.encap(p, false);

		delete thdr;

		// Store the packet into buffer
		WritablePacket *tmp = sk->send_buffer[sk->seq_num % sk->send_buffer_size];
		sk->send_buffer[sk->seq_num % sk->send_buffer_size] = copy_packet(p, sk);
		if (tmp)
			tmp->kill();

		// printf("XSEND: SENT DATA at (%s) seq=%d \n\n", dagstr.c_str(), sk->seq_num%sk->send_buffer_size);

		sk->seq_num++;
		sk->next_send_seqnum++;

		// Set timer
		sk->timer_on = true;
		sk->dataack_waiting = true;
		sk->num_retransmit_tries = 0;
		sk->expiry = Timestamp::now() + Timestamp::make_msec(_ackdelay_ms);

		if (! _timer.scheduled() || _timer.expiry() >= sk->expiry )
			_timer.reschedule_at(sk->expiry);

		portToSock.set(_sport, sk);

		//click_chatter("Sent packet to network");
		XIAHeader xiah1(p);
		String pld((char *)xiah1.payload(), xiah1.plen());
		//printf("\n\n (%s) send (timer set at %f) =%s  len=%d \n\n", (_local_addr.unparse()).c_str(), (sk->expiry).doubleval(), pld.c_str(), xiah1.plen());
		output(NETWORK_PORT).push(p);
	}

	x_send_msg->clear_payload(); // clear payload before returning result
	ReturnResult(_sport, xia_socket_msg, rc, ec);
}

void XTRANSPORT::Xsendto(unsigned short _sport, xia::XSocketMsg *xia_socket_msg, WritablePacket *p_in)
{
	int rc = 0, ec = 0;

	xia::X_Sendto_Msg *x_sendto_msg = xia_socket_msg->mutable_x_sendto();

	String dest(x_sendto_msg->ddag().c_str());
	int pktPayloadSize = x_sendto_msg->payload().size();
	//click_chatter("\n SENDTO ddag:%s, payload:%s, length=%d\n",xia_socket_msg.ddag().c_str(), xia_socket_msg.payload().c_str(), pktPayloadSize);

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

//	if (DEBUG)
//		click_chatter("sent packet from %s, to %s\n", sk->src_path.unparse_re().c_str(), dest.c_str());

	//Add XIA headers
	XIAHeaderEncap xiah;

	xiah.set_last(LAST_NODE_DEFAULT);
	xiah.set_hlim(hlim.get(_sport));
	xiah.set_dst_path(dst_path);
	xiah.set_src_path(sk->src_path);

	WritablePacket *just_payload_part = WritablePacket::make(p_in->headroom() + 1, (const void*)x_sendto_msg->payload().c_str(), pktPayloadSize, p_in->tailroom());

	WritablePacket *p = NULL;

	if (sk->sock_type == XSOCKET_RAW) {
		xiah.set_nxt(nxt_xport.get(_sport));

		xiah.set_plen(pktPayloadSize);
		p = xiah.encap(just_payload_part, false);

	} else {
		xiah.set_nxt(CLICK_XIA_NXT_TRN);
		xiah.set_plen(pktPayloadSize);

		//p = xiah.encap(just_payload_part, true);
		//printf("\n\nSEND: %s ---> %s\n\n", sk->src_path.unparse_re().c_str(), dest.c_str());
		//printf("payload=%s len=%d \n\n", x_sendto_msg->payload().c_str(), pktPayloadSize);

		//Add XIA Transport headers
		TransportHeaderEncap *thdr = TransportHeaderEncap::MakeDGRAMHeader(0); // length
		p = thdr->encap(just_payload_part);

		thdr->update();
		xiah.set_plen(pktPayloadSize + thdr->hlen()); // XIA payload = transport header + transport-layer data

		p = xiah.encap(p, false);
		delete thdr;
	}

	output(NETWORK_PORT).push(p);

	rc = pktPayloadSize;
	x_sendto_msg->clear_payload();
	ReturnResult(_sport, xia_socket_msg, rc, ec);
}

void XTRANSPORT::Xrecv(unsigned short _sport, xia::XSocketMsg *xia_socket_msg)
{
	sock *sk = portToSock.get(_sport);
	read_from_recv_buf(xia_socket_msg, sk);

	if (xia_socket_msg->x_recv().bytes_returned() > 0) {
		// Return response to API
		ReturnResult(_sport, xia_socket_msg, xia_socket_msg->x_recv().bytes_returned());
	} else if (!xia_socket_msg->blocking()) {
		// we're not blocking and there's no data, so let API know immediately
		sk->recv_pending = false;
		ReturnResult(_sport, xia_socket_msg, -1, EWOULDBLOCK);

	} else {
		// rather than returning a response, wait until we get data
		sk->recv_pending = true; // when we get data next, send straight to app

		// xia_socket_msg is saved on the stack; allocate a copy on the heap
		xia::XSocketMsg *xsm_cpy = new xia::XSocketMsg();
		xsm_cpy->CopyFrom(*xia_socket_msg);
		sk->pending_recv_msg = xsm_cpy;
	}
}

void XTRANSPORT::Xrecvfrom(unsigned short _sport, xia::XSocketMsg *xia_socket_msg)
{
	sock *sk = portToSock.get(_sport);
	read_from_recv_buf(xia_socket_msg, sk);

	if (xia_socket_msg->x_recvfrom().bytes_returned() > 0) {
		// Return response to API
		ReturnResult(_sport, xia_socket_msg, xia_socket_msg->x_recvfrom().bytes_returned());

	} else if (!xia_socket_msg->blocking()) {

		// we're not blocking and there's no data, so let API know immediately
		ReturnResult(_sport, xia_socket_msg, -1, EWOULDBLOCK);

	} else {
		// rather than returning a response, wait until we get data
		sk->recv_pending = true; // when we get data next, send straight to app

		// xia_socket_msg is saved on the stack; allocate a copy on the heap
		xia::XSocketMsg *xsm_cpy = new xia::XSocketMsg();
		xsm_cpy->CopyFrom(*xia_socket_msg);
		sk->pending_recv_msg = xsm_cpy;
	}
}

void XTRANSPORT::XrequestChunk(unsigned short _sport, xia::XSocketMsg *xia_socket_msg, WritablePacket *p_in)
{
	xia::X_Requestchunk_Msg *x_requestchunk_msg = xia_socket_msg->mutable_x_requestchunk();

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

void XTRANSPORT::XgetChunkStatus(unsigned short _sport, xia::XSocketMsg *xia_socket_msg)
{
	xia::X_Getchunkstatus_Msg *x_getchunkstatus_msg = xia_socket_msg->mutable_x_getchunkstatus();

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

void XTRANSPORT::XreadChunk(unsigned short _sport, xia::XSocketMsg *xia_socket_msg)
{
	xia::X_Readchunk_Msg *x_readchunk_msg = xia_socket_msg->mutable_x_readchunk();

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

			xia::X_Readchunk_Msg *x_readchunk_msg = xia_socket_msg->mutable_x_readchunk();
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

void XTRANSPORT::XremoveChunk(unsigned short _sport, xia::XSocketMsg *xia_socket_msg)
{
	xia::X_Removechunk_Msg *x_rmchunk_msg = xia_socket_msg->mutable_x_removechunk();

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

	xia::X_Removechunk_Msg *_msg = xia_socket_msg->mutable_x_removechunk();
	_msg->set_contextid(contextID);
	_msg->set_cid(src.c_str());
	_msg->set_status(0);

	ReturnResult(_sport, xia_socket_msg); // TODO: Error codes?
}

void XTRANSPORT::XputChunk(unsigned short _sport, xia::XSocketMsg *xia_socket_msg)
{
	xia::X_Putchunk_Msg *x_putchunk_msg = xia_socket_msg->mutable_x_putchunk();
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
EXPORT_ELEMENT(GenericConnHandler)
ELEMENT_REQUIRES(userlevel)
ELEMENT_REQUIRES(XIAContentModule)
ELEMENT_MT_SAFE(XTRANSPORT)
