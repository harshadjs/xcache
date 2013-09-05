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


#define UNUSED(x) ((void)(x))
/*
 * min()/max() macros that also do
 * strict type-checking.. See the
 * "unnecessary" pointer comparison.
 */
#define min(x,y) ({ \
	const typeof(x) _x = (x);	\
	const typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x < _y ? _x : _y; })

#define max(x,y) ({ \
	const typeof(x) _x = (x);	\
	const typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x > _y ? _x : _y; })
/*
 * ..and if you can't take the strict
 * types, you can specify one yourself.
 *
 * Or not use min/max at all, of course.
 */
#define min_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#define max_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })


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

#define REQUEST_FAILED		0x00000001
#define WAITING_FOR_CHUNK	0x00000002
#define READY_TO_READ		0x00000004
#define INVALID_HASH		0x00000008

#define HASH_KEYSIZE    20

#define API_PORT    0
#define BAD_PORT       1
#define NETWORK_PORT    2
#define CACHE_PORT      3
#define XHCP_PORT       4

// TODO: Are we going to keep this convenient value?
#define TCP_MSS_DEFAULT_XIA 1000

/* TCP params from http://lxr.linux.no/linux+v3.10.2/include/net/tcp.h */

/* Offer an initial receive window of 10 mss. */
#define TCP_DEFAULT_INIT_RCVWND	10

/* Minimal accepted MSS. It is (60+60+8) - (20+20). */
#define TCP_MIN_MSS		88U

/* The least MTU to use for probing */
#define TCP_BASE_MSS		512

/* After receiving this amount of duplicate ACKs fast retransmit starts. */
#define TCP_FASTRETRANS_THRESH 3

/* Maximal reordering. */
#define TCP_MAX_REORDERING	127

/* Maximal number of ACKs sent quickly to accelerate slow-start. */
#define TCP_MAX_QUICKACKS	16U


#define TCP_RETR1	3	/*
				 * This is how many retries it does before it
				 * tries to figure out if the gateway is
				 * down. Minimal RFC value is 3; it corresponds
				 * to ~3sec-8min depending on RTO.
				 */

#define TCP_RETR2	15	/*
				 * This should take at least
				 * 90 minutes to time out.
				 * RFC1122 says that the limit is 100 sec.
				 * 15 is ~13-30min depending on RTO.
				 */

#define TCP_SYN_RETRIES	 6	/* This is how many retries are done
				 * when active opening a connection.
				 * RFC1122 says the minimum retry MUST
				 * be at least 180secs.  Nevertheless
				 * this value is corresponding to
				 * 63secs of retransmission with the
				 * current initial RTO.
				 */

#define TCP_SYNACK_RETRIES 5	/* This is how may retries are done
				 * when passive opening a connection.
				 * This is corresponding to 31secs of
				 * retransmission with the current
				 * initial RTO.
				 */

#define TCP_TIMEWAIT_LEN (60*HZ) /* how long to wait to destroy TIME-WAIT
				  * state, about 60 seconds	*/
#define TCP_FIN_TIMEOUT	TCP_TIMEWAIT_LEN
                                 /* BSD style FIN_WAIT2 deadlock breaker.
				  * It used to be 3min, new value is 60sec,
				  * to combine FIN-WAIT-2 timeout with
				  * TIME-WAIT timer.
				  */

#define TCP_DELACK_MAX	((unsigned)(HZ/5))	/* maximal time to delay before sending an ACK */
#if HZ >= 100
#define TCP_DELACK_MIN	((unsigned)(HZ/25))	/* minimal time to delay before sending an ACK */
#define TCP_ATO_MIN	((unsigned)(HZ/25))
#else
#define TCP_DELACK_MIN	4U
#define TCP_ATO_MIN	4U
#endif
#define TCP_RTO_MAX	((unsigned)(120*HZ))
#define TCP_RTO_MIN	((unsigned)(HZ/5))
#define TCP_TIMEOUT_INIT ((unsigned)(1*HZ))	/* RFC6298 2.1 initial RTO value	*/
#define TCP_TIMEOUT_FALLBACK ((unsigned)(3*HZ))	/* RFC 1122 initial RTO value, now
						 * used as a fallback RTO for the
						 * initial data transmission if no
						 * valid RTT sample has been acquired,
						 * most likely due to retrans in 3WHS.
						 */

#define TCP_RESOURCE_PROBE_INTERVAL ((unsigned)(HZ/2U)) /* Maximal interval between probes
					                 * for local resources.
					                 */

#define TCP_KEEPALIVE_TIME	(120*60*HZ)	/* two hours */
#define TCP_KEEPALIVE_PROBES	9		/* Max of 9 keepalive probes	*/
#define TCP_KEEPALIVE_INTVL	(75*HZ)

#define MAX_TCP_KEEPIDLE	32767
#define MAX_TCP_KEEPINTVL	32767
#define MAX_TCP_KEEPCNT		127
#define MAX_TCP_SYNCNT		127

#define TCP_SYNQ_INTERVAL	(HZ/5)	/* Period of SYNACK timer */

#define TCP_PAWS_24DAYS	(60 * 60 * 24 * 24)
#define TCP_PAWS_MSL	60		/* Per-host timestamps are invalidated
					 * after this time. It should be equal
					 * (or greater than) TCP_TIMEWAIT_LEN
					 * to provide reliability equal to one
					 * provided by timewait state.
					 */
#define TCP_PAWS_WINDOW	1		/* Replay window for per-host
					 * timestamps. It must be less than
					 * minimal timewait lifetime.
					 */
/*
 *	TCP option
 */
 
#define TCPOPT_NOP		1	/* Padding */
#define TCPOPT_EOL		0	/* End of options */
#define TCPOPT_MSS		2	/* Segment size negotiating */


/*
 *     TCP option lengths
 */
#define TCPOLEN_MSS            4


/* But this is what stacks really send out. */
#define TCPOLEN_MSS_ALIGNED		4

/* Flags in tp->nonagle */
#define TCP_NAGLE_OFF		1	/* Nagle's algo is disabled */
#define TCP_NAGLE_CORK		2	/* Socket is corked	    */
#define TCP_NAGLE_PUSH		4	/* Cork is overridden for already queued data */

/* TCP thin-stream limits */
#define TCP_THIN_LINEAR_RETRIES 6       /* After 6 linear retries, do exp. backoff */

/* TCP initial congestion window as per draft-hkchu-tcpm-initcwnd-01 */
#define TCP_INIT_CWND		10

#define TCP_INFINITE_SSTHRESH 0x7fffffff

/*
 * TCP general constants (Can't find these in 3.10.2 src?)
 */
#define TCP_MSS_DEFAULT          536U   /* IPv4 (RFC1122, RFC2581) */
#define TCP_MSS_DESIRED         1220U   /* IPv6 (tunneled), EDNS0 (RFC3226) */

//  Definitions for the TCP protocol sk_state field.
enum {
	TCP_ESTABLISHED = 0,
	TCP_SYN_SENT,
	TCP_SYN_RECV,
	TCP_FIN_WAIT1,
	TCP_FIN_WAIT2,
	TCP_TIME_WAIT,
	TCP_CLOSE,
	TCP_CLOSE_WAIT,
	TCP_LAST_ACK,
	TCP_LISTEN,
	TCP_CLOSING,	/* Now a valid state */

	TCP_NSTATES	/* Leave at the end! */
};

/* 
 * (BSD)
 * Flags used when sending segments in tcp_output.  Basic flags (TH_RST,
 * TH_ACK,TH_SYN,TH_FIN) are totally determined by state, with the proviso
 * that TH_FIN is sent only if all data queued for output is included in the
 * segment. See definition of flags in xiatransportheader.hh
 */
static const uint8_t	tcp_outflags[TCP_NSTATES] = {
		TH_RST|TH_ACK,		/* 0, CLOSED */
		0,			/* 1, LISTEN */
		TH_SYN,			/* 2, SYN_SENT */
		TH_SYN|TH_ACK,		/* 3, SYN_RECEIVED */
		TH_ACK,			/* 4, ESTABLISHED */
		TH_ACK,			/* 5, CLOSE_WAIT */
		TH_FIN|TH_ACK,		/* 6, FIN_WAIT_1 */
		TH_FIN|TH_ACK,		/* 7, CLOSING */
		TH_FIN|TH_ACK,		/* 8, LAST_ACK */
		TH_ACK,			/* 9, FIN_WAIT_2 */
		TH_ACK,			/* 10, TIME_WAIT */
	};	


/* tcp_input.c defines */
#define FLAG_DATA		0x01 /* Incoming frame contained data.		*/
#define FLAG_WIN_UPDATE		0x02 /* Incoming ACK was a window update.	*/
#define FLAG_DATA_ACKED		0x04 /* This ACK acknowledged new data.		*/
#define FLAG_RETRANS_DATA_ACKED	0x08 /* "" "" some of which was retransmitted.	*/
#define FLAG_SYN_ACKED		0x10 /* This ACK acknowledged SYN.		*/
#define FLAG_DATA_SACKED	0x20 /* New SACK.				*/
#define FLAG_ECE		0x40 /* ECE in this ACK				*/
#define FLAG_DATA_LOST		0x80 /* SACK detected data lossage.		*/
#define FLAG_SLOWPATH		0x100 /* Do not skip RFC checks for window update.*/

#define FLAG_ACKED		(FLAG_DATA_ACKED|FLAG_SYN_ACKED)
#define FLAG_NOT_DUP		(FLAG_DATA|FLAG_WIN_UPDATE|FLAG_ACKED)
#define FLAG_CA_ALERT		(FLAG_DATA_SACKED|FLAG_ECE)
#define FLAG_FORWARD_PROGRESS	(FLAG_ACKED|FLAG_DATA_SACKED)

#define IsReno(tp) ((tp)->sack_ok == 0)
#define IsFack(tp) ((tp)->sack_ok & 2)
#define IsDSack(tp) ((tp)->sack_ok & 4)

#define TCP_REMNANT (TCP_FLAG_FIN|TCP_FLAG_URG|TCP_FLAG_SYN|TCP_FLAG_PSH)


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



class XTRANSPORT : public Element { 
  public:
    XTRANSPORT();
    ~XTRANSPORT();
    const char *class_name() const		{ return "XTRANSPORT"; }
    const char *port_count() const		{ return "5/4"; }
    const char *processing() const		{ return PUSH; }
    int configure(Vector<String> &, ErrorHandler *);         
    void push(int port, Packet *);            
    XID local_hid() { return _local_hid; };
    XIAPath local_addr() { return _local_addr; };
    XID local_4id() { return _local_4id; };
    void add_handlers();
    static int write_param(const String &, Element *, void *vparam, ErrorHandler *);
    
    int initialize(ErrorHandler *);
    void run_timer(Timer *timer);

    void ReturnResult(int sport, xia::XSocketMsg *xia_socket_msg, int rc = 0, int err = 0);
    
  private:
//  pthread_mutex_t _lock;
//  pthread_mutexattr_t _lock_attr;

    Timer _timer;
    
    unsigned _ackdelay_ms;
    unsigned _teardown_wait_ms;
    
    uint32_t _cid_type, _sid_type;
    XID _local_hid;
    XIAPath _local_addr;
    XID _local_4id;
    XID _null_4id;
    bool _is_dual_stack_router;
    bool isConnected;
    XIAPath _nameserver_addr;

    Packet* UDPIPPrep(Packet *, int);


/* TODO: sock (previously named DAGinfo) stores per-socket states for ALL transport protocols. We better make a specialized struct for each protocol
*	(e.g., xsp_sock, tcp_sock) that is inherited from sock struct. Not sure if HashTable<XID, sock> will work. Use HashTable<XID, sock*> instead?
*/

	/* =========================
	 * Socket states
	 * ========================= */
    struct sock {
    	sock(): port(0), isConnected(false), initialized(false), full_src_dag(false), timer_on(false), synack_waiting(false), dataack_waiting(false), teardown_waiting(false), send_buffer_size(DEFAULT_SEND_WIN_SIZE), recv_buffer_size(DEFAULT_RECV_WIN_SIZE), send_base(0), next_send_seqnum(0), recv_base(0), next_recv_seqnum(0), dgram_buffer_start(0), dgram_buffer_end(-1), recv_buffer_count(0), recv_pending(false) {};

	/* =========================
	 * Common Socket states
	 * ========================= */
		unsigned short port;
		XIAPath src_path;
		XIAPath dst_path;
		int nxt;
		int last;
		uint8_t hlim;

		unsigned char sk_state;		// e.g. TCP connection state for tcp_sock

		bool full_src_dag; // bind to full dag or just to SID  
		int sock_type; // 0: Reliable transport (SID), 1: Unreliable transport (SID), 2: Content Chunk transport (CID)
		String sdag;
		String ddag;

	/* =========================
	 * XSP/XChunkP Socket states
	 * ========================= */

		bool isConnected;
		bool initialized;
//		bool synack_waiting;
		bool dataack_waiting;
		bool teardown_waiting;

		int num_connect_tries; // number of xconnect tries (Xconnect will fail after MAX_CONNECT_TRIES trials)
		int num_retransmit_tries; // number of times to try resending data packets

    	queue<sock*> pending_connection_buf;
		queue<xia::XSocketMsg*> pendingAccepts; // stores accept messages from API when there are no pending connections
	
		// send buffer
    	WritablePacket *send_buffer[MAX_SEND_WIN_SIZE]; // packets we've sent but have not gotten an ACK for // TODO: start smaller, dynamically resize if app asks for more space (up to MAX)?
		uint32_t send_buffer_size;
    	uint32_t send_base; // the sequence # of the oldest unacked packet
    	uint32_t next_send_seqnum; // the smallest unused sequence # (i.e., the sequence # of the next packet to be sent)
		uint32_t remote_recv_window; // num additional *packets* the receiver has room to buffer

		// receive buffer
    	WritablePacket *recv_buffer[MAX_RECV_WIN_SIZE]; // packets we've received but haven't delivered to the app // TODO: start smaller, dynamically resize if app asks for more space (up to MAX)?
		uint32_t recv_buffer_size; // the number of PACKETS we can buffer (received but not delivered to app)
		uint32_t recv_base; // sequence # of the oldest received packet not delivered to app
    	uint32_t next_recv_seqnum; // the sequence # of the next in-order packet we expect to receive
		int dgram_buffer_start; // the first undelivered index in the recv buffer (DGRAM only)
		int dgram_buffer_end; // the last undelivered index in the recv buffer (DGRAM only)
		uint32_t recv_buffer_count; // the number of packets in the buffer (DGRAM only)
		bool recv_pending; // true if we should send received network data to app upon receiving it
		xia::XSocketMsg *pending_recv_msg;

		//Vector<WritablePacket*> pkt_buf;
		WritablePacket *syn_pkt;
		HashTable<XID, WritablePacket*> XIDtoCIDreqPkt;
		HashTable<XID, Timestamp> XIDtoExpiryTime;
		HashTable<XID, bool> XIDtoTimerOn;
		HashTable<XID, int> XIDtoStatus; // Content-chunk request status... 1: waiting to be read, 0: waiting for chunk response, -1: failed
		HashTable<XID, bool> XIDtoReadReq; // Indicates whether ReadCID() is called for a specific CID
		HashTable<XID, WritablePacket*> XIDtoCIDresponsePkt;
		uint32_t seq_num;
		uint32_t ack_num;
		bool timer_on;
		Timestamp expiry;
		Timestamp teardown_expiry;

	/* =========================================================
	 * TCP Socket states 
	 * http://lxr.linux.no/linux+v3.10.2/include/linux/tcp.h
	 * ========================================================= */
		
		//uint16_t	tcp_header_len;	/* Bytes of tcp header to send		*/

	/*
	 *	Header prediction flags
	 *	0x5?10 << 16 + snd_wnd in net byte order
	 */
	//	uint32_t	pred_flags;

	/*
	 *	RFC793 variables by their proper names. This means you can
	 *	read the code and the spec side by side (and laugh ...)
	 *	See RFC793 and RFC1122. The RFC writes these in capitals.
	 */
	 	uint32_t	rcv_nxt;	/* What we want to receive next 	*/
		uint32_t	copied_seq;	/* Head of yet unread data		*/
		uint32_t	rcv_wup;	/* rcv_nxt on last window update sent	*/
	 	uint32_t	snd_nxt;	/* Next sequence we send		*/

	 	uint32_t	snd_una;	/* First byte we want an ack for	*/
	 	uint32_t	snd_sml;	/* Last byte of the most recently transmitted small packet */
		uint32_t	rcv_tstamp;	/* timestamp of last received ACK (for keepalives) */
		uint32_t	lsndtime;	/* timestamp of last sent data packet (for restart window) */

		 /* Delayed ACK control data */
		struct {
			uint8_t	pending;	/* ACK is pending */
			uint8_t	quick;		/* Scheduled number of quick acks	*/
			uint8_t	pingpong;	/* The session is interactive		*/
			uint8_t	blocked;	/* Delayed ACK was blocked by socket lock*/
			uint32_t	ato;		/* Predicted tick of soft clock		*/
			unsigned long timeout;	/* Currently scheduled timeout		*/
			uint32_t	lrcvtime;	/* timestamp of last received data packet*/
			uint16_t	last_seg_size;	/* Size of last incoming segment	*/
			uint16_t	rcv_mss;	/* MSS used for delayed ACK decisions	*/ 
		} ack;

		uint32_t	tsoffset;	/* timestamp offset */


		uint32_t	snd_wl1;	/* Sequence for window update		*/
		uint32_t	snd_wnd;	/* The window we expect to receive	*/
		uint32_t	max_window;	/* Maximal window ever seen from peer	*/
		uint32_t	mss_cache;	/* Cached effective mss, not including SACKS */

		uint32_t	window_clamp;	/* Maximal window to advertise		*/
		uint32_t	rcv_ssthresh;	/* Current window clamp			*/

		uint16_t	advmss;		/* Advertised MSS			*/
		uint8_t	unused;
		uint8_t	nonagle     : 4,/* Disable Nagle algorithm?             */
			thin_lto    : 1,/* Use linear timeouts for thin streams */
			thin_dupack : 1,/* Fast retransmit on first dupack      */
			repair      : 1,
			frto        : 1;/* F-RTO (RFC5682) activated in CA_Loss */
		uint8_t	repair_queue;
		uint8_t	do_early_retrans:1,/* Enable RFC5827 early-retransmit  */
			syn_data:1,	/* SYN includes data */
			syn_fastopen:1,	/* SYN includes Fast Open option */
			syn_data_acked:1;/* data in SYN is acked by SYN-ACK */
		uint32_t	tlp_high_seq;	/* snd_nxt at the time of TLP retransmit. */

	/* RTT measurement */
		uint8_t		backoff;	/* backoff	(2.4.20)				*/
		uint32_t	srtt;		/* smoothed round trip time << 3	*/
		uint32_t	mdev;		/* medium deviation			*/
		uint32_t	mdev_max;	/* maximal mdev for the last rtt period	*/
		uint32_t	rttvar;		/* smoothed mdev_max			*/
		uint32_t	rtt_seq;	/* sequence number to update rttvar	*/
		uint32_t 	rto;		/* retransmit timemout 				*/

		uint32_t	packets_out;	/* Packets which are "in flight"	*/
		uint32_t	retrans_out;	/* Retransmitted packets out		*/

		uint8_t retransmits; /* Number of unrecovered RTO timeouts(2.4.20)	*/

		uint8_t	reordering;	/* Packet reordering metric.		*/

		uint8_t	keepalive_probes; /* num of allowed keep alive probes	*/

	/*	PAWS/RTTM data	*/
		long	ts_recent_stamp;/* Time we stored ts_recent (for aging) */
		uint32_t	ts_recent;	/* Time stamp to echo next		*/
		uint32_t	rcv_tsval;	/* Time stamp value             	*/
		uint32_t	rcv_tsecr;	/* Time stamp echo reply        	*/
		uint16_t 	saw_tstamp : 1,	/* Saw TIMESTAMP on last packet		*/
			tstamp_ok : 1,	/* TIMESTAMP seen on SYN packet		*/
			dsack : 1,	/* D-SACK is scheduled			*/
			wscale_ok : 1,	/* Wscale seen on SYN packet		*/
			sack_ok : 4,	/* SACK seen on SYN packet		*/
			snd_wscale : 4,	/* Window scaling received from sender	*/
			rcv_wscale : 4;	/* Window scaling to send to receiver	*/
		uint8_t	num_sacks;	/* Number of SACK blocks		*/
		uint16_t	user_mss;	/* mss requested by user in ioctl	*/
		uint16_t	mss_clamp;	/* Maximal mss, negotiated at connection setup */

	/*
	 *	Slow start and congestion control (see also Nagle, and Karn & Partridge)
	 */
	 	uint32_t	snd_ssthresh;	/* Slow start size threshold		*/
	 	uint32_t	snd_cwnd;	/* Sending congestion window		*/
		uint32_t	snd_cwnd_cnt;	/* Linear increase counter		*/
		uint32_t	snd_cwnd_clamp; /* Do not allow snd_cwnd to grow above this */
		uint32_t	snd_cwnd_used;
		uint32_t	snd_cwnd_stamp;
		uint32_t	prior_cwnd;	/* Congestion window at start of Recovery. */
		uint32_t	prr_delivered;	/* Number of newly delivered packets to
					 * receiver in Recovery. */
		uint32_t	prr_out;	/* Total number of pkts sent during Recovery. */

	 	uint32_t	rcv_wnd;	/* Current receiver window		*/
		uint32_t	write_seq;	/* Tail(+1) of data held in tcp send buffer */
		uint32_t	pushed_seq;	/* Last pushed seq, required to talk to windows */
		uint32_t	lost_out;	/* Lost packets			*/
		uint32_t	sacked_out;	/* SACK'd packets			*/
		uint32_t	fackets_out;	/* FACK'd packets			*/
		uint32_t	tso_deferred;

		// TODO: SACK block readded?

		int     lost_cnt_hint;
		uint32_t     retransmit_high;	/* L-bits may be on up to this seqno */

		uint32_t	lost_retrans_low;	/* Sent seq after any rxmit (lowest) */

		uint32_t	prior_ssthresh; /* ssthresh saved at recovery start	*/
		uint32_t	high_seq;	/* snd_nxt at onset of congestion	*/

		uint32_t	retrans_stamp;	/* Timestamp of the last retransmit,
					 * also used in SYN-SENT to remember stamp of
					 * the first SYN. */
		uint32_t	undo_marker;	/* tracking retrans started here. */
		int	undo_retrans;	/* number of undoable retransmissions. */
		uint32_t	total_retrans;	/* Total retransmits for entire connection */

		unsigned int		keepalive_time;	  /* time before keep alive takes place */
		unsigned int		keepalive_intvl;  /* time interval between keep alive probes */

		int			linger2;

	/* Receiver side RTT estimation */
		struct {
			uint32_t	rtt;
			uint32_t	seq;
			uint32_t	time;
		} rcv_rtt_est;

	/* Receiver queue space */
		struct {
			int	space;
			uint32_t	seq;
			uint32_t	time;
		} rcvq_space;    


		/* http://lxr.linux.no/linux-old+v2.4.20/include/net/tcp.h
		 *
		 * This is what the send packet queueing engine uses to pass
		 * TCP per-packet control information to the transmission
		 * code.  We also store the host-order sequence numbers in
		 * here too.  This is 36 bytes on 32-bit architectures,
		 * 40 bytes on 64-bit machines, if this grows please adjust
		 * skbuff.h:skbuff->cb[xxx] size appropriately.
		 */
		struct tcp_skb_cb {
			
			uint32_t		seq;		/* Starting sequence number	*/
			uint32_t		end_seq;	/* SEQ + FIN + SYN + datalen	*/
			uint32_t		when;		/* used to compute rtt's	*/
			uint8_t		flags;		/* TCP header flags.		*/

			/* NOTE: These must match up to the flags byte in a
			 *       real TCP header.
			 */
		#define TCPCB_FLAG_FIN		0x01
		#define TCPCB_FLAG_SYN		0x02
		#define TCPCB_FLAG_RST		0x04
		#define TCPCB_FLAG_PSH		0x08
		#define TCPCB_FLAG_ACK		0x10
		#define TCPCB_FLAG_URG		0x20
		#define TCPCB_FLAG_ECE		0x40
		#define TCPCB_FLAG_CWR		0x80

			uint8_t		sacked;		/* State flags for SACK/FACK.	*/
		#define TCPCB_SACKED_ACKED	0x01	/* SKB ACK'd by a SACK block	*/
		#define TCPCB_SACKED_RETRANS	0x02	/* SKB retransmitted		*/
		#define TCPCB_LOST		0x04	/* SKB is lost			*/
		#define TCPCB_TAGBITS		0x07	/* All tag bits			*/

		#define TCPCB_EVER_RETRANS	0x80	/* Ever retransmitted frame	*/
		#define TCPCB_RETRANS		(TCPCB_SACKED_RETRANS|TCPCB_EVER_RETRANS)

		#define TCPCB_URG		0x20	/* Urgent pointer advenced here	*/

		#define TCPCB_AT_TAIL		(TCPCB_URG)

			uint32_t		ack_seq;	/* Sequence number ACK'd	*/
		};

		struct tcp_skb_cb tcp_cb[MAX_SEND_WIN_SIZE];

    } ;


 
    list<int> xcmp_listeners;   // list of ports wanting xcmp notifications

    HashTable<XID, unsigned short> XIDtoPort;
    HashTable<XIDpair , unsigned short> XIDpairToPort;
    HashTable<unsigned short, sock*> portToSock;

    HashTable<unsigned short, bool> portToActive;
    HashTable<XIDpair , bool> XIDpairToConnectPending;

    // FIXME: can these be rolled into the sock structure?
	HashTable<unsigned short, int> nxt_xport;
    HashTable<unsigned short, int> hlim;

    
    atomic_uint32_t _id;
    bool _cksum;
    XIAXIDRouteTable *_routeTable;
    
    //modify routing table
    void addRoute(const XID &sid) {
		String cmd=sid.unparse() + " " + String(DESTINED_FOR_LOCALHOST);
        HandlerCall::call_write(_routeTable, "add", cmd);
    }   
        
    void delRoute(const XID &sid) {
        String cmd= sid.unparse();
        HandlerCall::call_write(_routeTable, "remove", cmd);
    }
 

 
  protected:    
    void copy_common(struct sock *sk, XIAHeader &xiahdr, XIAHeaderEncap &xiah);
    WritablePacket* copy_packet(Packet *, struct sock *);
    WritablePacket* copy_cid_req_packet(Packet *, struct sock *);
    WritablePacket* copy_cid_response_packet(Packet *, struct sock *);

    char *random_xid(const char *type, char *buf);

    /*
    ** TCP helper functions (tcp.h/c)
    */
    void tcp_set_state(struct sock *sk, int state);
    int before(uint32_t seq1, uint32_t seq2)
	{
        return (int32_t)(seq1-seq2) < 0;
	}

	int after(uint32_t seq1, uint32_t seq2)
	{
		return (int32_t)(seq2-seq1) < 0;
	}

	/* is s2<=s1<=s3 ? */
	int between(uint32_t seq1, uint32_t seq2, uint32_t seq3)
	{
		return seq3 - seq2 >= seq1 - seq2;
	}
	/* Called to compute a smoothed rtt estimate. The data fed to this
	 * routine either comes from timestamps, or from segments that were
	 * known _not_ to have been retransmitted [see Karn/Partridge
	 * Proceedings SIGCOMM 87]. The algorithm is from the SIGCOMM 88
	 * piece by Van Jacobson.
	 * NOTE: the next three routines used to be one big routine.
	 * To save cycles in the RFC 1323 implementation it was better to break
	 * it up into three procedures. -- erics
	 */
	void tcp_rtt_estimator(struct sock *sk, const uint32_t mrtt)
	{
		struct sock *tp = sk;
		long m = mrtt; /* RTT */

		/*	The following amusing code comes from Jacobson's
		 *	article in SIGCOMM '88.  Note that rtt and mdev
		 *	are scaled versions of rtt and mean deviation.
		 *	This is designed to be as fast as possible
		 *	m stands for "measurement".
		 *
		 *	On a 1990 paper the rto value is changed to:
		 *	RTO = rtt + 4 * mdev
		 *
		 * Funny. This algorithm seems to be very broken.
		 * These formulae increase RTO, when it should be decreased, increase
		 * too slowly, when it should be increased quickly, decrease too quickly
		 * etc. I guess in BSD RTO takes ONE value, so that it is absolutely
		 * does not matter how to _calculate_ it. Seems, it was trap
		 * that VJ failed to avoid. 8)
		 */
		if (m == 0)
			m = 1;
		if (tp->srtt != 0) {
			m -= (tp->srtt >> 3);	/* m is now error in rtt est */
			tp->srtt += m;		/* rtt = 7/8 rtt + 1/8 new */
			if (m < 0) {
				m = -m;		/* m is now abs(error) */
				m -= (tp->mdev >> 2);   /* similar update on mdev */
				/* This is similar to one of Eifel findings.
				 * Eifel blocks mdev updates when rtt decreases.
				 * This solution is a bit different: we use finer gain
				 * for mdev in this case (alpha*beta).
				 * Like Eifel it also prevents growth of rto,
				 * but also it limits too fast rto decreases,
				 * happening in pure Eifel.
				 */
				if (m > 0)
					m >>= 3;
			} else {
				m -= (tp->mdev >> 2);   /* similar update on mdev */
			}
			tp->mdev += m;	    	/* mdev = 3/4 mdev + 1/4 new */
			if (tp->mdev > tp->mdev_max) {
				tp->mdev_max = tp->mdev;
				if (tp->mdev_max > tp->rttvar)
					tp->rttvar = tp->mdev_max;
			}
			if (after(tp->snd_una, tp->rtt_seq)) {
				if (tp->mdev_max < tp->rttvar)
					tp->rttvar -= (tp->rttvar - tp->mdev_max) >> 2;
				tp->rtt_seq = tp->snd_nxt;
				tp->mdev_max = TCP_RTO_MIN; // FIXME: is it ok to replace tcp_rto_min(sk) with TCP_RTO_MIN?
			}
		} else {
			/* no previous measure. */
			tp->srtt = m << 3;	/* take the measured time to be rtt */
			tp->mdev = m << 1;	/* make sure rto = 3*rtt */
			tp->mdev_max = tp->rttvar = max(tp->mdev, TCP_RTO_MIN); // FIXME: same as above
			tp->rtt_seq = tp->snd_nxt;
		}
	}

	/* Calculate rto without backoff.  This is the second half of Van Jacobson's
	 * routine referred to above.
	 */
	void tcp_set_rto(struct sock *sk)
	{
		sk->rto = (sk->srtt >> 3) + sk->rttvar;
		// Bound RTO
		if (sk->rto > TCP_RTO_MAX)
		    sk->rto = TCP_RTO_MAX;
	}

	/* Increase initial CWND conservatively: if estimated
	 * RTT is low enough (<20msec) or if we have some preset ssthresh.
	 *
	 * Numbers are taken from RFC2414.
	 */
	uint32_t tcp_init_cwnd(struct sock *tp)
	{
		uint32_t cwnd;

		if (tp->mss_cache > 1460)
			return 2;

		cwnd = (tp->mss_cache > 1095) ? 3 : 4;

		if (!tp->srtt || (tp->snd_ssthresh >= 0xFFFF && tp->srtt > ((HZ/50)<<3)))
			cwnd = 2;
		else if (cwnd > tp->snd_ssthresh)
			cwnd = tp->snd_ssthresh;

		return min_t(uint32_t, cwnd, tp->snd_cwnd_clamp);
	}

	/* Initialize metrics on socket. */

	void tcp_init_metrics(struct sock *tp)
	{
		/* Removed code related to dst_entry since we don't have destination cache */

		/* Play conservative. If timestamps are not
		 * supported, TCP will fail to recalculate correct
		 * rtt, if initial rto is too small. FORGET ALL AND RESET!
		 */
		if (!tp->saw_tstamp && tp->srtt) {
			tp->srtt = 0;
			tp->mdev = tp->mdev_max = tp->rttvar = TCP_TIMEOUT_INIT;
			tp->rto = TCP_TIMEOUT_INIT;
		}
	}

	void tcp_initialize_rcv_mss(struct sock *tp)
	{
		unsigned int hint = min(tp->advmss, tp->mss_cache);

		hint = min(hint, tp->rcv_wnd/2);
		hint = min(hint, TCP_MIN_RCVMSS);
		hint = max(hint, TCP_MIN_MSS);

		tp->ack.rcv_mss = hint;
	}

	void tcp_done(struct sock *sk)
	{
		tcp_set_state(sk, TCP_CLOSE);
		//tcp_clear_xmit_timers(sk); TODO:
	}

	int tcp_ack(struct sock *sk, TransportHeader *thdr, int flag)
	{
		struct sock *tp = sk;
		uint32_t prior_snd_una = tp->snd_una;
		uint32_t ack_seq = thdr->seq_num();
		uint32_t ack = thdr->ack_num();
		uint32_t prior_in_flight;
		int prior_packets;

		/* If the ack is newer than sent or older than previous acks
		 * then we can probably ignore it.
		 */
		if (after(ack, tp->snd_nxt))
			goto uninteresting_ack;

		if (before(ack, prior_snd_una))
			goto old_ack;

		if (!(flag&FLAG_SLOWPATH) && after(ack, prior_snd_una)) {
			/* Window is constant, pure forward advance.
			 * No more checks are required.
			 * Note, we use the fact that SND.UNA>=SND.WL2.
			 */
			tcp_update_wl(tp, ack, ack_seq);
			tp->snd_una = ack;
			flag |= FLAG_WIN_UPDATE;

		} else {
			if (ack_seq != TCP_SKB_CB(skb)->end_seq)
				flag |= FLAG_DATA;

			flag |= tcp_ack_update_window(sk, tp, skb, ack, ack_seq);

			/*
			if (TCP_SKB_CB(skb)->sacked)
				flag |= tcp_sacktag_write_queue(sk, skb, prior_snd_una);

			if (TCP_ECN_rcv_ecn_echo(tp, skb->h.th))
				flag |= FLAG_ECE;
			*/
		}

		/* We passed data and got it acked, remove any soft error
		 * log. Something worked...
		 */
		sk->err_soft = 0;
		tp->rcv_tstamp = tcp_time_stamp;
		if ((prior_packets = tp->packets_out) == 0)
			goto no_queue;

		prior_in_flight = tcp_packets_in_flight(tp);

		/* See if we can take anything off of the retransmit queue. */
		flag |= tcp_clean_rtx_queue(sk);

		if (tcp_ack_is_dubious(tp, flag)) {
			/* Advanve CWND, if state allows this. */
			if ((flag&FLAG_DATA_ACKED) && prior_in_flight >= tp->snd_cwnd &&
			    tcp_may_raise_cwnd(tp, flag))
				tcp_cong_avoid(tp);
			tcp_fastretrans_alert(sk, prior_snd_una, prior_packets, flag);
		} else {
			if ((flag&FLAG_DATA_ACKED) && prior_in_flight >= tp->snd_cwnd)
				tcp_cong_avoid(tp);
		}

		if ((flag & FLAG_FORWARD_PROGRESS) || !(flag&FLAG_NOT_DUP))
			dst_confirm(sk->dst_cache);

		return 1;

	no_queue:
		tp->probes_out = 0;

		/* If this ack opens up a zero window, clear backoff.  It was
		 * being used to time the probes, and is probably far higher than
		 * it needs to be for normal retransmission.
		 */
		if (tp->send_head)
			tcp_ack_probe(sk);
		return 1;

	old_ack:
		if (TCP_SKB_CB(skb)->sacked)
			tcp_sacktag_write_queue(sk, skb, prior_snd_una);

	uninteresting_ack:
		SOCK_DEBUG(sk, "Ack %u out of %u:%u\n", ack, tp->snd_una, tp->snd_nxt);
		return 0;
	}



	uint32_t calc_recv_window(sock *sk);
	bool should_buffer_received_packet(WritablePacket *p, sock *sk);
	void add_packet_to_recv_buf(WritablePacket *p, sock *sk);
	void check_for_and_handle_pending_recv(sock *sk);
	int read_from_recv_buf(xia::XSocketMsg *xia_socket_msg, sock *sk);
	uint32_t next_missing_seqnum(sock *sk);
	void resize_buffer(WritablePacket* buf[], int max, int type, uint32_t old_size, uint32_t new_size, int *dgram_start, int *dgram_end);
	void resize_send_buffer(sock *sk, uint32_t new_size);
	void resize_recv_buffer(sock *sk, uint32_t new_size);

    void ProcessAPIPacket(WritablePacket *p_in);
    void ProcessNetworkPacket(WritablePacket *p_in);
    void ProcessCachePacket(WritablePacket *p_in);
    void ProcessXhcpPacket(WritablePacket *p_in);
    /*
    ** Xsockets API handlers
    */
    void Xsocket(unsigned short _sport, xia::XSocketMsg *xia_socket_msg);
    void Xsetsockopt(unsigned short _sport, xia::XSocketMsg *xia_socket_msg);
    void Xgetsockopt(unsigned short _sport, xia::XSocketMsg *xia_socket_msg);
    void Xbind(unsigned short _sport, xia::XSocketMsg *xia_socket_msg);
    void Xclose(unsigned short _sport, xia::XSocketMsg *xia_socket_msg);
    void Xconnect(unsigned short _sport, xia::XSocketMsg *xia_socket_msg);
	void XreadyToAccept(unsigned short _sport, xia::XSocketMsg *xia_socket_msg);
    void Xaccept(unsigned short _sport, xia::XSocketMsg *xia_socket_msg);
    void Xchangead(unsigned short _sport, xia::XSocketMsg *xia_socket_msg);
    void Xreadlocalhostaddr(unsigned short _sport, xia::XSocketMsg *xia_socket_msg);
    void Xupdatenameserverdag(unsigned short _sport, xia::XSocketMsg *xia_socket_msg);
    void Xreadnameserverdag(unsigned short _sport, xia::XSocketMsg *xia_socket_msg);
    void Xgetpeername(unsigned short _sport, xia::XSocketMsg *xia_socket_msg);
    void Xgetsockname(unsigned short _sport, xia::XSocketMsg *xia_socket_msg);    
    void Xisdualstackrouter(unsigned short _sport, xia::XSocketMsg *xia_socket_msg);
    void Xsend(unsigned short _sport, xia::XSocketMsg *xia_socket_msg, WritablePacket *p_in);
    void Xsendto(unsigned short _sport, xia::XSocketMsg *xia_socket_msg, WritablePacket *p_in);
	void Xrecv(unsigned short _sport, xia::XSocketMsg *xia_socket_msg);
	void Xrecvfrom(unsigned short _sport, xia::XSocketMsg *xia_socket_msg);
    void XrequestChunk(unsigned short _sport, xia::XSocketMsg *xia_socket_msg, WritablePacket *p_in);
    void XgetChunkStatus(unsigned short _sport, xia::XSocketMsg *xia_socket_msg);
    void XreadChunk(unsigned short _sport, xia::XSocketMsg *xia_socket_msg);
    void XremoveChunk(unsigned short _sport, xia::XSocketMsg *xia_socket_msg);
    void XputChunk(unsigned short _sport, xia::XSocketMsg *xia_socket_msg);
};


CLICK_ENDDECLS

#endif
