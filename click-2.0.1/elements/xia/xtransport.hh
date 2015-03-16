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
using namespace xia;
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

enum HandlerState { CREATE, INITIALIZE, ACTIVE, SHUTDOWN, CLOSE };
class XGenericTransport {
public:
    friend class XTRANSPORT;
    XGenericTransport (XTRANSPORT *transport, const unsigned short port, int type);

    virtual void push(const int port, Packet *p) = 0 ;
    virtual Packet *pull(const int port) = 0;
    int read_from_recv_buf(XSocketMsg *xia_socket_msg);
    virtual ~XGenericTransport();
    const unsigned short get_port() {return port;}
    int get_type() { return type; }
    void set_state(const HandlerState s) {state = s;}
    HandlerState get_state() { return state; }
    XIAPath get_src_path() {return src_path;}
    void set_src_path(XIAPath p) {src_path = p;}
    XIAPath get_dst_path() {return dst_path;}
    void set_dst_path(XIAPath p) {dst_path = p;}
    int get_nxt() {return nxt;}
    void set_nxt(int n) {nxt = n;}
    int get_last() {return last;}
    void set_last(int n) {last = n;}
    uint8_t get_hlim() {return hlim;}
    void set_hlim(uint8_t n) {hlim = n;}
    bool is_full_src_dag() {return full_src_dag;}
    void set_full_src_dag(bool f) {full_src_dag = f;}
    String get_sdag() {return sdag;}
    void set_sdag(String s) {sdag = s;}
    String get_ddag() {return ddag;}
    void set_ddag(String s) {ddag = s;}
    bool is_did_poll() {return did_poll;}
    void set_did_poll(bool d) {did_poll = d;}
    unsigned get_polling() {return polling;}
    void increase_polling() {polling++;}
    void decrease_polling() {polling--;}
    bool is_recv_pending() {return recv_pending;}
    void set_recv_pending(bool r) {recv_pending = r;}
    XSocketMsg get_pending_recv_msg() {return pending_recv_msg;}
    void set_pending_recv_msg(XSocketMsg *msg) {pending_recv_msg = msg;}
    XIDpair get_key() {return key;}
    void set_key(XIDpair k) {key = k;}
protected:

    XTRANSPORT *get_transport() const { return transport; }

    unsigned short port;
    XTRANSPORT *transport;
    HandlerState state;
    XIAPath src_path;
    XIAPath dst_path;
    XIDpair key;

    int nxt;
    int last;
    uint8_t hlim;


    bool full_src_dag; // bind to full dag or just to SID
    int type; // 0: Reliable transport (SID), 1: Unreliable transport (SID), 2: Content Chunk transport (CID)
    String sdag;
    String ddag;

    bool did_poll;
    unsigned polling;
    bool recv_pending; // true if we should send received network data to app upon receiving it
    XSocketMsg *pending_recv_msg;
    ErrorHandler    *_errh;

private:
    XGenericTransport() { };
};

typedef HashTable<XIDpair, XGenericTransport*>::iterator ConnIterator; 

class XTRANSPORT : public Element {

    friend class XGenericTransport;

public:
    XTRANSPORT();
    ~XTRANSPORT();
    const char *class_name() const      { return "XTRANSPORT"; }
    const char *port_count() const      { return "5/4"; }
    const char *processing() const      { return PUSH; }
    int configure(Vector<String> &, ErrorHandler *);
    void push(int port, Packet *);
    XID local_hid() { return _local_hid; };
    XIAPath local_addr() { return _local_addr; };
    XID local_4id() { return _local_4id; };
    void add_handlers();
    static int write_param(const String &, Element *, void *vparam, ErrorHandler *);

    int initialize(ErrorHandler *);
    void ReturnResult(int sport, XSocketMsg *xia_socket_msg, int rc = 0, int err = 0);
    ErrorHandler *error_handler()   { return _errh; }

private:

    uint32_t _cid_type, _sid_type;
    XID _local_hid;
    XIAPath _local_addr;
    XID _local_4id;
    XID _null_4id;
    bool _is_dual_stack_router;
    XIAPath _nameserver_addr;

    Packet* UDPIPPrep(Packet *, int);

    /* Legacy fields, to be modified later */
    list<int> xcmp_listeners;   // list of ports wanting xcmp notifications

    /* Core data structures */
    HashTable<XIDpair, XGenericTransport*> pairToHandler;  // network packet
    HashTable<unsigned short, XGenericTransport*> portToHandler;   // API packet

    int num_connections;

    HashTable<unsigned short, PollEvent> poll_events;

    XIAXIDRouteTable *_routeTable;

    //modify routing table
    void addRoute(const XID &sid) {
        String cmd = sid.unparse() + " " + String(DESTINED_FOR_LOCALHOST);
        HandlerCall::call_write(_routeTable, "add", cmd);
    }

    void delRoute(const XID &sid) {
        String cmd = sid.unparse();
        HandlerCall::call_write(_routeTable, "remove", cmd);
    }

public:
    void copy_common(struct sock *sk, XIAHeader &xiahdr, XIAHeaderEncap &xiah);
    WritablePacket* copy_packet(Packet *, struct sock *);
    WritablePacket* copy_cid_req_packet(Packet *, struct sock *);
    WritablePacket* copy_cid_response_packet(Packet *, struct sock *);

    char *random_xid(const char *type, char *buf);

    // uint32_t calc_recv_window(sock *sk);
    // bool should_buffer_received_packet(WritablePacket *p, sock *sk);
    // void add_packet_to_recv_buf(WritablePacket *p, sock *sk);
    // void check_for_and_handle_pending_recv(sock *sk);
    // uint32_t next_missing_seqnum(sock *sk);
    // void resize_buffer(WritablePacket* buf[], int max, int type, uint32_t old_size, uint32_t new_size, int *dgram_start, int *dgram_end);
    // void resize_send_buffer(sock *sk, uint32_t new_size);
    // void resize_recv_buffer(sock *sk, uint32_t new_size);

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
    void Xsocket(unsigned short _sport, XSocketMsg *xia_socket_msg);
    void Xsetsockopt(unsigned short _sport, XSocketMsg *xia_socket_msg);
    void Xgetsockopt(unsigned short _sport, XSocketMsg *xia_socket_msg);
    void Xbind(unsigned short _sport, XSocketMsg *xia_socket_msg);
    void Xclose(unsigned short _sport, XSocketMsg *xia_socket_msg);
    void Xconnect(unsigned short _sport, XSocketMsg *xia_socket_msg);
    void XreadyToAccept(unsigned short _sport, XSocketMsg *xia_socket_msg);
    void Xaccept(unsigned short _sport, XSocketMsg *xia_socket_msg);
    void Xchangead(unsigned short _sport, XSocketMsg *xia_socket_msg);
    void Xreadlocalhostaddr(unsigned short _sport, XSocketMsg *xia_socket_msg);
    void Xupdatenameserverdag(unsigned short _sport, XSocketMsg *xia_socket_msg);
    void Xreadnameserverdag(unsigned short _sport, XSocketMsg *xia_socket_msg);
    void Xgetpeername(unsigned short _sport, XSocketMsg *xia_socket_msg);
    void Xgetsockname(unsigned short _sport, XSocketMsg *xia_socket_msg);
    void Xisdualstackrouter(unsigned short _sport, XSocketMsg *xia_socket_msg);
    void Xsend(unsigned short _sport, XSocketMsg *xia_socket_msg, WritablePacket *p_in);
    void Xsendto(unsigned short _sport, XSocketMsg *xia_socket_msg, WritablePacket *p_in);
    void Xrecv(unsigned short _sport, XSocketMsg *xia_socket_msg);
    void Xrecvfrom(unsigned short _sport, XSocketMsg *xia_socket_msg);
    void XrequestChunk(unsigned short _sport, XSocketMsg *xia_socket_msg, WritablePacket *p_in);
    void XgetChunkStatus(unsigned short _sport, XSocketMsg *xia_socket_msg);
    void XreadChunk(unsigned short _sport, XSocketMsg *xia_socket_msg);
    void XremoveChunk(unsigned short _sport, XSocketMsg *xia_socket_msg);
    void XputChunk(unsigned short _sport, XSocketMsg *xia_socket_msg);
    void Xpoll(unsigned short _sport, XSocketMsg *xia_socket_msg);

private:

    /* Newly added fields and functions */

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
    tcp_globals *globals()  { return &_tcp_globals; }
    uint32_t tcp_now()      { return _tcp_globals.tcp_now; }
    int verbosity()             { return _verbosity; }
    // Element Handler Methods
    static String read_verb(Element*, void*);
    static int write_verb(const String&, Element*, void*, ErrorHandler*);
    static String read_num_connections(Element*, void*);

    ErrorHandler    *_errh;
    tcpstat         _tcpstat;
    Timer           *_fast_ticks;
    Timer           *_slow_ticks;
    int         _verbosity;

    tcp_globals     _tcp_globals;
    int verbosity;
};

XGenericTransport::XGenericTransport(
    XTRANSPORT *transport,
    const unsigned short port,
    int type) : state(CREATE) {
    port = port;
    transport = transport;
    type = type;
    _errh = transport -> error_handler();
    hlim = HLIM_DEFAULT;
    nxt = CLICK_XIA_NXT_TRN;
}


CLICK_ENDDECLS

#endif
