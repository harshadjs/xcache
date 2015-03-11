// -*- c-basic-offset: 4; related-file-name: "../../lib/xiatransportheader.cc" -*-
#ifndef CLICK_TRANSPORTEXTHEADER_HH
#define CLICK_TRANSPORTEXTHEADER_HH
#include <click/string.hh>
#include <click/glue.hh>
#include <clicknet/xia.h>
#include <click/packet.hh>
#include <click/hashtable.hh>
#include <click/xiaheader.hh>
#include <click/xiaextheader.hh>
#include <click/xid.hh>

CLICK_DECLS

class TransportHeaderEncap;

class TransportHeader : public XIAGenericExtHeader {
public:
    TransportHeader(const struct click_xia_ext* hdr) : XIAGenericExtHeader(hdr) {};
    TransportHeader(const Packet* p): XIAGenericExtHeader(p) {};

    uint8_t type() { if (!exists(TYPE)) return 0 ; return *(const uint8_t*)_map[TYPE].data();};

    // need to type check, but first ignore here
    void* header() {
        if (!exists(HEADER)) return NULL;
        return (void *)_map[HEADER].data();
    }
    void set_header
    enum { XSOCK_STREAM = 1, XSOCK_DGRAM, XSOCK_RAW, XSOCK_CHUNK};

};

class TransportHeaderEncap : public XIAGenericExtHeaderEncap {
public:
    TransportHeaderEncap::TransportHeaderEncap(char type);
    /* data length contained in the packet*/
    //TransportHeaderEncap(uint16_t offset, uint32_t chunk_offset, uint16_t length, uint32_t chunk_length, char opcode= TransportHeader::OP_RESPONSE);

    // //TransportHeaderEncap(char type, char pkt_info, XID src_xid, XID dst_xid, uint32_t seq_num, uint32_t ack_num, uint16_t length);
    // TransportHeaderEncap(char type, char pkt_info, uint32_t seq_num, uint32_t ack_num, uint16_t length, uint32_t recv_window);

    // //static TransportHeaderEncap* MakeRequestHeader() { return new TransportHeaderEncap(TransportHeader::OP_REQUEST,0,0); };
    // //static TransportHeaderEncap* MakeRPTRequestHeader() { return new TransportHeaderEncap(TransportHeader::OP_REDUNDANT_REQUEST,0,0); };

    static TransportHeaderEncap* MakeTCPHeader(struct click_tcp *tcph);

    static TransportHeaderEncap* MakeUDPHeader(struct click_udp *udph);

    // static TransportHeaderEncap* MakeDATAHeader( uint32_t seq_num, uint32_t ack_num, uint16_t length, uint32_t recv_window )
    //                     { return new TransportHeaderEncap(TransportHeader::XSOCK_STREAM, TransportHeader::DATA, seq_num, ack_num, length, recv_window); };

    // static TransportHeaderEncap* MakeACKHeader( uint32_t seq_num, uint32_t ack_num, uint16_t length, uint32_t recv_window )
    //                     { return new TransportHeaderEncap(TransportHeader::XSOCK_STREAM, TransportHeader::ACK, seq_num, ack_num, length, recv_window); };

    // static TransportHeaderEncap* MakeFINHeader( uint32_t seq_num, uint32_t ack_num, uint16_t length, uint32_t recv_window )
    //                     { return new TransportHeaderEncap(TransportHeader::XSOCK_STREAM, TransportHeader::FIN, seq_num, ack_num, length, recv_window); };

    // static TransportHeaderEncap* MakeDGRAMHeader( uint16_t length )
    //                     { return new TransportHeaderEncap(TransportHeader::XSOCK_DGRAM, TransportHeader::DATA, -1, -1, length, -1); };

};


CLICK_ENDDECLS
#endif
