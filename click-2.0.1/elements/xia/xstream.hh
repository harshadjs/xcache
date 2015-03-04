#ifndef CLICK_XTRANSPORT_HH
#define CLICK_XTRANSPORT_HH

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
#endif

// FIXME: put these in a std location that can be found by click and the API
#define XOPT_HLIM 0x07001
#define XOPT_NEXT_PROTO 0x07002

#ifndef DEBUG
#define DEBUG 0
#endif


#define UNUSED(x) ((void)(x))

#define ACK_DELAY           300
#define TEARDOWN_DELAY      240000
#define HLIM_DEFAULT        250
#define LAST_NODE_DEFAULT   -1
#define RANDOM_XID_FMT      "%s:30000ff0000000000000000000000000%08x"
#define UDP_HEADER_SIZE     8

#define XSOCKET_INVALID -1  // invalid socket type  
#define XSOCKET_STREAM  1   // Reliable transport (SID)
#define XSOCKET_DGRAM   2   // Unreliable transport (SID)
#define XSOCKET_RAW     3   // Raw XIA socket
#define XSOCKET_CHUNK   4   // Content Chunk transport (CID)

// TODO: switch these to bytes, not packets?
#define MAX_SEND_WIN_SIZE 256  // in packets, not bytes
#define MAX_RECV_WIN_SIZE 256
#define DEFAULT_SEND_WIN_SIZE 128
#define DEFAULT_RECV_WIN_SIZE 128

#define MAX_CONNECT_TRIES    30
#define MAX_RETRANSMIT_TRIES 100

#define REQUEST_FAILED      0x00000001
#define WAITING_FOR_CHUNK   0x00000002
#define READY_TO_READ       0x00000004
#define INVALID_HASH        0x00000008

#define HASH_KEYSIZE    20

#define API_PORT    0
#define BAD_PORT       1
#define NETWORK_PORT    2
#define CACHE_PORT      3
#define XHCP_PORT       4


// /* TCP params from http://lxr.linux.no/linux+v3.10.2/include/net/tcp.h */

// /* Offer an initial receive window of 10 mss. */
// #define TCP_DEFAULT_INIT_RCVWND 10

// /* Minimal accepted MSS. It is (60+60+8) - (20+20). */
// #define TCP_MIN_MSS     88U

// /* The least MTU to use for probing */
// #define TCP_BASE_MSS        512

// /* After receiving this amount of duplicate ACKs fast retransmit starts. */
// #define TCP_FASTRETRANS_THRESH 3

// /* Maximal reordering. */
// #define TCP_MAX_REORDERING  127

// /* Maximal number of ACKs sent quickly to accelerate slow-start. */
// #define TCP_MAX_QUICKACKS   16U


// #define TCP_RETR1   3   /*
//                  * This is how many retries it does before it
//                  * tries to figure out if the gateway is
//                  * down. Minimal RFC value is 3; it corresponds
//                  * to ~3sec-8min depending on RTO.
//                  */

// #define TCP_RETR2   15  /*
//                  * This should take at least
//                  * 90 minutes to time out.
//                  * RFC1122 says that the limit is 100 sec.
//                  * 15 is ~13-30min depending on RTO.
//                  */

// #define TCP_SYN_RETRIES  6  /* This is how many retries are done
//                  * when active opening a connection.
//                  * RFC1122 says the minimum retry MUST
//                  * be at least 180secs.  Nevertheless
//                  * this value is corresponding to
//                  * 63secs of retransmission with the
//                  * current initial RTO.
//                  */

// #define TCP_SYNACK_RETRIES 5    /* This is how may retries are done
//                  * when passive opening a connection.
//                  * This is corresponding to 31secs of
//                  * retransmission with the current
//                  * initial RTO.
//                  */

// #define TCP_TIMEWAIT_LEN (60*HZ) /* how long to wait to destroy TIME-WAIT
//                   * state, about 60 seconds */
// #define TCP_FIN_TIMEOUT TCP_TIMEWAIT_LEN
// /* BSD style FIN_WAIT2 deadlock breaker.
// * It used to be 3min, new value is 60sec,
//         * to combine FIN-WAIT-2 timeout with
//         * TIME-WAIT timer.
//         */

// #define TCP_DELACK_MAX  ((unsigned)(HZ/5))  /* maximal time to delay before sending an ACK */
// #if HZ >= 100
// #define TCP_DELACK_MIN  ((unsigned)(HZ/25)) /* minimal time to delay before sending an ACK */
// #define TCP_ATO_MIN ((unsigned)(HZ/25))
// #else
// #define TCP_DELACK_MIN  4U
// #define TCP_ATO_MIN 4U
// #endif
// #define TCP_RTO_MAX ((unsigned)(120*HZ))
// #define TCP_RTO_MIN ((unsigned)(HZ/5))
// #define TCP_TIMEOUT_INIT ((unsigned)(1*HZ)) /* RFC6298 2.1 initial RTO value    */
// #define TCP_TIMEOUT_FALLBACK ((unsigned)(3*HZ)) /* RFC 1122 initial RTO value, now
//                          * used as a fallback RTO for the
//                          * initial data transmission if no
//                          * valid RTT sample has been acquired,
//                          * most likely due to retrans in 3WHS.
//                          */

// #define TCP_RESOURCE_PROBE_INTERVAL ((unsigned)(HZ/2U)) /* Maximal interval between probes
//                                      * for local resources.
//                                      */

// #define TCP_KEEPALIVE_TIME  (120*60*HZ) /* two hours */
// #define TCP_KEEPALIVE_PROBES    9       /* Max of 9 keepalive probes    */
// #define TCP_KEEPALIVE_INTVL (75*HZ)

// #define MAX_TCP_KEEPIDLE    32767
// #define MAX_TCP_KEEPINTVL   32767
// #define MAX_TCP_KEEPCNT     127
// #define MAX_TCP_SYNCNT      127

// #define TCP_SYNQ_INTERVAL   (HZ/5)  /* Period of SYNACK timer */

// #define TCP_PAWS_24DAYS (60 * 60 * 24 * 24)
// #define TCP_PAWS_MSL    60      /* Per-host timestamps are invalidated
//                      * after this time. It should be equal
//                      * (or greater than) TCP_TIMEWAIT_LEN
//                      * to provide reliability equal to one
//                      * provided by timewait state.
//                      */
// #define TCP_PAWS_WINDOW 1       /* Replay window for per-host
//                      * timestamps. It must be less than
//                      * minimal timewait lifetime.
//                      */
// /*
//  *  TCP option
//  */

// #define TCPOPT_NOP      1   /* Padding */
// #define TCPOPT_EOL      0   /* End of options */
// #define TCPOPT_MSS      2   /* Segment size negotiating */


// /*
//  *     TCP option lengths
//  */
// #define TCPOLEN_MSS            4


// /* But this is what stacks really send out. */
// #define TCPOLEN_MSS_ALIGNED     4

// /* Flags in tp->nonagle */
// #define TCP_NAGLE_OFF       1   /* Nagle's algo is disabled */
// #define TCP_NAGLE_CORK      2   /* Socket is corked     */
// #define TCP_NAGLE_PUSH      4   /* Cork is overridden for already queued data */

// /* TCP thin-stream limits */
// #define TCP_THIN_LINEAR_RETRIES 6       /* After 6 linear retries, do exp. backoff */

// /* TCP initial congestion window as per draft-hkchu-tcpm-initcwnd-01 */
// #define TCP_INIT_CWND       10

// #define TCP_INFINITE_SSTHRESH 0x7fffffff

// //  Definitions for the TCP protocol sk_state field.
// enum {
// 	TCP_ESTABLISHED = 0,
// 	TCP_SYN_SENT,
// 	TCP_SYN_RECV,
// 	TCP_FIN_WAIT1,
// 	TCP_FIN_WAIT2,
// 	TCP_TIME_WAIT,
// 	TCP_CLOSE,
// 	TCP_CLOSE_WAIT,
// 	TCP_LAST_ACK,
// 	TCP_LISTEN,
// 	TCP_CLOSING,    /* Now a valid state */

// 	TCP_NSTATES /* Leave at the end! */
// };

/*
 * (BSD)
 * Flags used when sending segments in tcp_output.  Basic flags (TH_RST,
 * TH_ACK,TH_SYN,TH_FIN) are totally determined by state, with the proviso
 * that TH_FIN is sent only if all data queued for output is included in the
 * segment. See definition of flags in xiatransportheader.hh
 */
//static const uint8_t  tcp_outflags[TCP_NSTATES] = {
//      TH_RST|TH_ACK,      /* 0, CLOSED */
//      0,          /* 1, LISTEN */
//      TH_SYN,         /* 2, SYN_SENT */
//      TH_SYN|TH_ACK,      /* 3, SYN_RECEIVED */
//      TH_ACK,         /* 4, ESTABLISHED */
//      TH_ACK,         /* 5, CLOSE_WAIT */
//      TH_FIN|TH_ACK,      /* 6, FIN_WAIT_1 */
//      TH_FIN|TH_ACK,      /* 7, CLOSING */
//      TH_FIN|TH_ACK,      /* 8, LAST_ACK */
//      TH_ACK,         /* 9, FIN_WAIT_2 */
//      TH_ACK,         /* 10, TIME_WAIT */
//  };

CLICK_DECLS

/**
XTRANSPORT:
input port[0]:  api port
input port[1]:  Unused
input port[2]:  Network Rx data port
input port[3]:  in from cache

output[3]: To cache for putCID
output[2]: Network Tx data port
output[0]: Socket (API) Tx data port

Might need other things to handle chunking
*/

class XIAContentModule;


// Queue of packets from transport to socket layer
class TCPQueue { 

    class TCPQueueElt { 
		public: 
		TCPQueueElt(WritablePacket *p, tcp_seq_t s, tcp_seq_t n) { 
			_p = p; 
			seq = s; 
			seq_nxt = n; 
			nxt = NULL;
		}

		~TCPQueueElt() {}; 
		WritablePacket 	*_p;
		TCPQueueElt 	*nxt; 
		tcp_seq_t		seq; 
		tcp_seq_t		seq_nxt; 
	};

    public: 
    TCPQueue(TCPConnection *con);
    ~TCPQueue(); 

	int push(WritablePacket *p, tcp_seq_t seq, tcp_seq_t seq_nxt);
	void loop_last();
	WritablePacket *pull_front();

	// @Harald: Aren't all of these seq num arithmetic operations unsafe from
	// wraparound ?
	tcp_seq_t first() { return _q_first ? _q_first->seq : 0; }
	tcp_seq_t first_len() { return _q_first ? (_q_first->seq_nxt - _q_first->seq) : 0; }
	tcp_seq_t expected() { return _q_tail ? _q_tail->seq_nxt : 0; }
	tcp_seq_t tailseq() { return _q_tail ? _q_tail->seq : 0; }
	tcp_seq_t last()  { return _q_last ? _q_last->seq : 0; } 
	tcp_seq_t last_nxt()  { return _q_last ? _q_last->seq_nxt : 0; } 
	tcp_seq_t bytes_ok() { return _q_last ? _q_last->seq - _q_first->seq : 0; } 
	bool is_empty() { return _q_first ? false : true; }
	//FIXME: Returns true even if there is a hole at the front! Decide whether
	//to rethink what we mean by "ordered"
	bool is_ordered() { return (_q_last == _q_tail); }

    StringAccum * pretty_print(StringAccum &sa, int width); 

    private: 
	int verbosity() const;
    TCPConnection *_con;   /* The TCPConnection to which I belong */

    TCPQueueElt *_q_first; /* The first segment in the queue 
							 (a.k.a. the head element) */
    TCPQueueElt *_q_last;  /* The last segment of ordered data 
							 in the queue (a.k.a. the last 
							 segment before a gap occurs)  */
    TCPQueueElt *_q_tail;   /* The very last segment in the queue 
							 (a.k.a. the next expected in-order 
							 ariving segment should be inserted
							 after this segment )  */
};

// Queue of packets from socket layer to transport
class TCPFifo 
{ 
	public:
#define FIFO_SIZE 256
    TCPFifo(TCPConnection *con);
    ~TCPFifo(); 
    int 	push(WritablePacket *);
    int 	pkt_length() { return (_head - _tail) % FIFO_SIZE; }
    bool 	is_empty() { return ( 0 == pkt_length()) ; }
    int 	pkts_to_send(int offset, int win); 
    void 	drop_until (tcp_seq_t offset); 

    tcp_seq_t byte_length() { return _bytes; } 
    WritablePacket *pull(); 
    WritablePacket *get (tcp_seq_t offset); 

	protected:
    WritablePacket **_q; 
    int 	_head; 
    int 	_tail; 
    int 	_peek_cache_position; 
    int 	_peek_cache_offset; 
    tcp_seq_t _bytes;

	private:
    TCPConnection *_con;   /* The TCPConnection to which I belong */
	int verbosity() const;
};

/* =========================
 * Socket states
 * ========================= */
class TCPConnection  : public XGenericTrans {

	friend class XTRANSPORT;

public:
	TCPConnection(XTRANSPORT *, const unsigned int port);
		~TCPConnection() {
	    debug_output(VERB_MFD_QUEUES, 
	    "***** DELETING TCPConnection at <%x> ***** \n",
	    this); }; 
	
	void 	tcp_input(WritablePacket *p);
	void    push(const int port, Packet *p); 

	void 	tcp_output();
	int		usrsend(WritablePacket *p); 
	void    usrclosed() ; 
	void 	usropen(); 

#define SO_STATE_HASDATA	0x01
#define SO_STATE_ISCHOKED   0x10

	short state() const { return tp->t_state; } 
	bool has_pullable_data() { return !_q_recv.is_empty() && SEQ_LT(_q_recv.first(), tp->rcv_nxt); } 
	void print_state(StringAccum &sa); 
	int verbosity() const;

protected: 
	friend class XTRANSPORT; 

    void 		fasttimo();
	void 		slowtimo();
	void		tcp_timers(int timer); 

private: 
	ErrorHandler	*_errh; 
	tcpcb 		*tp;
	TCPFifo		_q_usr_input;
	TCPQueue	_q_recv; 
	tcp_seq_t	so_recv_buffer_size; 

	int			_so_state; 
	void 		_tcp_dooptions(u_char *cp, int cnt, const click_tcp *ti, 
					int *ts_present, u_long *ts_val, u_long *ts_ecr);
	void 		tcp_respond(tcp_seq_t ack, tcp_seq_t seq, int flags);
	void		tcp_setpersist(); 
	void		tcp_drop(int err); 
	void		tcp_xmit_timer(short rtt); 
	void 		tcp_canceltimers(); 
	u_int		tcp_mss(u_int); 
	tcpcb*		tcp_newtcpcb(); 
	tcp_seq_t	so_recv_buffer_space(); 

	// TODO: change to XIP header processing
	void 		_do_iphdr(WritablePacket *p);
	void 		ip_output(WritablePacket *p); 

	inline void tcp_set_state(short);
	inline void print_tcpstats(WritablePacket *p, char *label);
	short tcp_state() const { return tp->t_state; } 

	XIAPath src_path;
	XIAPath dst_path;
	int nxt;
	int last;
	uint8_t hlim;

	unsigned char sk_state;     // e.g. TCP connection state for tcp_sock

	bool full_src_dag; // bind to full dag or just to SID
	int sock_type; // 0: Reliable transport (SID), 1: Unreliable transport (SID), 2: Content Chunk transport (CID)
	String sdag;
	String ddag;

	/* =========================
	 * XSP/XChunkP Socket states
	 * ========================= */
	 // Do we need all of them??

	bool isConnected;
	bool initialized;
	bool isAcceptSocket;
	bool synack_waiting;
	bool dataack_waiting;
	bool teardown_waiting;

	bool did_poll;
	unsigned polling;

	int num_connect_tries; // number of xconnect tries (Xconnect will fail after MAX_CONNECT_TRIES trials)
	int num_retransmit_tries; // number of times to try resending data packets

	queue<sock *> pending_connection_buf;
	queue<xia::XSocketMsg *> pendingAccepts; // stores accept messages from API when there are no pending connections


	HashTable<XID, WritablePacket *> XIDtoCIDreqPkt;
	HashTable<XID, Timestamp> XIDtoExpiryTime;
	HashTable<XID, bool> XIDtoTimerOn;
	HashTable<XID, int> XIDtoStatus; // Content-chunk request status... 1: waiting to be read, 0: waiting for chunk response, -1: failed
	HashTable<XID, bool> XIDtoReadReq; // Indicates whether ReadCID() is called for a specific CID
	HashTable<XID, WritablePacket *> XIDtoCIDresponsePkt;

	Timestamp expiry;
	Timestamp teardown_expiry;



} ;

/* THE method where we register, and handle any TCP State Updates */
inline void 
TCPConnection::tcp_set_state(short state) {
	    short old = tp->t_state; 
	    StringAccum sa;
	    sa << *(flowid()); 
	    tp->t_state = state; 
		debug_output(VERB_STATES, "[%s] Flow: [%s]: State: [%s]->[%s]", speaker()->name().c_str(), sa.c_str(), tcpstates[old], tcpstates[tp->t_state]); 

		/* Set stateless flags which will dispatch the appropriately flagged
		 * signal packets into the mesh when we enter into one of these
		 * following states
		 */

		 /* stateless flags are disabled for now untill a better
		  * way of handling those is found */

		switch (state) {
			case TCPS_ESTABLISHED:
				set_state(ACTIVE);
				debug_output(VERB_STATES, "[%s] Flow: [%s]: Setting stateless SYN: [%d]", speaker()->name().c_str(), sa.c_str(), tp->t_sl_flags);
				break;
	//		case TCPS_CLOSE_WAIT:
			case TCPS_FIN_WAIT_1: 
			case TCPS_LAST_ACK:
				// tp->t_sl_flags = TH_FIN;
				/* 
				for (int port = 0; port <= 2; port++) 
				if ( ( output_port_dispatch(port) & MFD_DISPATCH_SCHEDULER) == MFD_DISPATCH_MFD_DIRECT ) { 
				    static_cast<MultiFlowHandler *>(output(port))->shutdown(output(port).remote_port()); 
				} 
				*/
				set_state(SHUTDOWN); 
				debug_output(VERB_STATES, "[%s] Flow: [%s]: Setting stateless FIN: [%d]", speaker()->name().c_str(), sa.c_str(), tp->t_sl_flags);
				break;
			case TCPS_CLOSED:
				set_state(CLOSE); 
				// tp->t_sl_flags = TH_RST;
				debug_output(VERB_STATES, "[%s] Flow: [%s]: Setting stateless RST: [%d]", speaker()->name().c_str(), sa.c_str(), tp->t_sl_flags);
				break;
		}
	};

	inline TCPSpeaker *
TCPConnection::speaker() const { return dynamic_cast<TCPSpeaker*>(mfd()); } 

inline int
TCPConnection::verbosity() const { return speaker()->verbosity(); }

inline int
TCPQueue::verbosity() const { return _con->speaker()->verbosity(); }

inline int
TCPFifo::verbosity() const { return _con->speaker()->verbosity(); }

	

CLICK_ENDDECLS

#endif
