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
#include <click/xipflowid.h>

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

typedef struct {
	bool forever;
	Timestamp expiry;
	HashTable<unsigned short, unsigned int> events;
} PollEvent;

struct mini_tcpip
{
    uint16_t ti_len;
    uint16_t ti_seq;
    uint16_t ti_ack;
    uint16_t ti_off;
    uint16_t ti_flags;
    uint16_t ti_win;
    uint16_t ti_urp;
};

struct tcp_globals 
{ 
        int     tcp_keepidle; 
        int     tcp_keepintvl; 
        int     tcp_maxidle; 
        int     tcp_mssdflt; 
        int     tcp_rttdflt; 
        int     so_flags;
        int     so_idletime; 
        int     window_scale; 
        bool    use_timestamp; 
        uint32_t tcp_now;
        tcp_seq_t so_recv_buffer_size; 
};

enum HandlerState { CREATE, INITIALIZE, ACTIVE, SHUTDOWN, CLOSE }; 
class GenericConnHandler { 
    public:

    /** @brief Constructor, do not use default constructor 
    * @param mfd The MultiFlowDispatcher that the handler is associated * with
    * @param port The port number for this connection
    * 
    * Creates a transport connection handler. This constructor should always be called
    * even if it is overwirtten */
    GenericConnHandler (
        XTRANSPORT *transport, 
        const XIPFlowID &flowid,
        int type);  

    virtual void push(const int port, Packet *p) = 0 ;
    virtual Packet *pull(const int port) = 0;
    virtual ~GenericConnHandler(); 
    
    int get_type() { return type; }
    // virtual HandlerState set_state(const HandlerState new_state, const int input_port = -1); 
    HandlerState set_state(const HandlerState s) {state = s;}
    HandlerState get_state(){ return state; } 

protected:

    /** @brief returns the Dispatcher that the Handler is associated with
    * 
    * @return The MultiFlowDispatcher */
    XTRANSPORT *get_transport() const { return transport; }
    XIPFlowID* flowid() {return flowid;}
//     // Next 3 lines formerly declared protected
//     void set_q_membership(int qid)  { /* click_chatter("q_mem %d", q_membership); */ q_membership |= (1 << qid); } 
//     void del_q_membership(int qid)  { q_membership &= ~(1 <<qid); }
//     bool is_q_member(int qid)       { 
//         bool ismember = (q_membership >> qid) & 1;
// //      click_chatter("DEBUG [%x] mfh::is_q_member: member of queue [%d]? [%s] q_mem: [%d]", this, qid, (ismember?"true":"false"), q_membership); 
//         return ismember; 
//     } 

    private: 

    GenericConnHandler() { };
    XIPFlowID flowid;
    XTRANSPORT *transport;
    int type;   // 0: Reliable transport (SID), 1: Unreliable transport (SID), 2: Content Chunk transport (CID)
    HandlerState state;
    friend class XTRANSPORT;
};

typedef HashTable<XIPFlowID, GenericConnHandler*>::iterator ConnIterator; 

class XTRANSPORT : public Element { 

    friend class GenericConnHandler;
    
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

    void ReturnResult(int sport, xia::XSocketMsg *xia_socket_msg, int rc = 0, int err = 0);
    
  private:

    uint32_t _cid_type, _sid_type;
    XID _local_hid;
    XIAPath _local_addr;
    XID _local_4id;
    XID _null_4id;
    bool _is_dual_stack_router;
    bool isConnected;
    XIAPath _nameserver_addr;

    Packet* UDPIPPrep(Packet *, int);

    /* Legacy fields, to be modified later */
    list<int> xcmp_listeners;   // list of ports wanting xcmp notifications

    /* Core data structures */
    HashTable<XIPFlowID, GenericConnHandler*> conn_handlers;
    ConnIterator conn_iterator;
    int num_connections;
    // FIXME: can these be rolled into the sock structure?
	HashTable<unsigned short, int> nxt_xport;
    HashTable<unsigned short, int> hlim;

    HashTable<unsigned short, PollEvent> poll_events;

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
    GenericConnHandler* Get_handler_by_src_port(const unsigned int port);

    void copy_common(struct sock *sk, XIAHeader &xiahdr, XIAHeaderEncap &xiah);
    WritablePacket* copy_packet(Packet *, struct sock *);
    WritablePacket* copy_cid_req_packet(Packet *, struct sock *);
    WritablePacket* copy_cid_response_packet(Packet *, struct sock *);

    char *random_xid(const char *type, char *buf);

	uint32_t calc_recv_window(sock *sk);
	bool should_buffer_received_packet(WritablePacket *p, sock *sk);
	void add_packet_to_recv_buf(WritablePacket *p, sock *sk);
	void check_for_and_handle_pending_recv(sock *sk);
	int read_from_recv_buf(xiaha::XSocketMsg *xia_socket_msg, sock *sk);
	uint32_t next_missing_seqnum(sock *sk);
	void resize_buffer(WritablePacket* buf[], int max, int type, uint32_t old_size, uint32_t new_size, int *dgram_start, int *dgram_end);
	void resize_send_buffer(sock *sk, uint32_t new_size);
	void resize_recv_buffer(sock *sk, uint32_t new_size);

    void ProcessAPIPacket(WritablePacket *p_in);
    void ProcessNetworkPacket(WritablePacket *p_in);
    void ProcessCachePacket(WritablePacket *p_in);
    void ProcessXhcpPacket(WritablePacket *p_in);

    void CreatePollEvent(unsigned short _sport, xia::X_Poll_Msg *msg);
    void ProcessPollEvent(unsigned short, unsigned int);
    void CancelPollEvent(unsigned short _sport);
//    bool ProcessPollTimeout(unsigned short, PollEvent& pe);
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
    void Xpoll(unsigned short _sport, xia::XSocketMsg *xia_socket_msg);


    /* Newly added fields and functions */

public:
    ConnIterator Get_conn_iterator() { return conn_iterator; }
    int Get_num_connections() { return num_connections; }


private:
    TCPConnection * new_handler(const unsigned int port) { 
        return new TCPConnection(this, port);
    }

    virtual GenericConnHandler *new_handler(const unsigned short port) = 0;
    void add_handler(GenericConnHandler *handler); // or this one?
    void remove_handler(GenericConnHandler *handler);
        /** @brief check whether this packet can create a new connection
    * 
    * @param packet The packet to check
    * 
    * This can be overwritten, if the protocol has dedicated "syn"
    * packets. (e.g. tcp checks for "exactly syn flag set")
    * additional actions (such as sending a reset) can also be
    * performed here 
    *
    * The default returns always true. 
    * 
    * 
    */
    bool is_syn(const Packet * ); 
    ErrorHandler *error_handler()   { return _errh; }
    tcp_globals *globals()  { return &_tcp_globals; } 
    uint32_t tcp_now()      { return _tcp_globals.tcp_now; }
    int verbosity()             { return _verbosity; }
    // Element Handler Methods
    static String read_verb(Element*, void*);
    static int write_verb(const String&, Element*, void*, ErrorHandler*);
    static String read_num_connections(Element*, void*);
    void        run_timer(Timer *); 
    int         iter_connections(void *, int);

    ErrorHandler    *_errh; 
    tcpstat         _tcpstat; 
        Timer           *_fast_ticks;
    Timer           *_slow_ticks;
    int         _verbosity;
    ErrorHandler    *errhandler; 
    tcp_globals     _tcp_globals; 
    int verbosity;



};

GenericConnHandler::GenericConnHandler(
        XTRANSPORT *transport, 
        const XIPFlowID &flowid,
        int type) : state(CREATE){
    flowid = flowid;
    transport = transport;
    type = type;
}


CLICK_ENDDECLS

#endif
