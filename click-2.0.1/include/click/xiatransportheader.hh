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

class TransportHeader : public XIAGenericExtHeader { public:
    TransportHeader(const struct click_xia_ext* hdr) :XIAGenericExtHeader(hdr) {};
    TransportHeader(const Packet* p):XIAGenericExtHeader(p) {};

    uint8_t type() { if (!exists(TYPE)) return 0 ; return *(const uint8_t*)_map[TYPE].data();}; 
    
    bool exists(uint8_t key) { return (_map.find(key)!=_map.end()); }
    
    //uint8_t pkt_info() { if (!exists(PKT_INFO)) return 0 ; return *(const uint8_t*)_map[PKT_INFO].data();}; 
    //uint16_t length() { if (!exists(LENGTH)) return 0; return *(const uint16_t*)_map[LENGTH].data();};  

	uint32_t seq_num() { if (!exists(SEQ_NUM)) return 0; return *(const uint32_t*)_map[SEQ_NUM].data();};  
    uint32_t ack_num() { if (!exists(ACK_NUM)) return 0; return *(const uint32_t*)_map[ACK_NUM].data();};  
    uint32_t offset() { if (!exists(OFFSET)) return 0; return *(const uint8_t*)_map[OFFSET].data();};  
    uint32_t flags() { if (!exists(FLAGS)) return 0; return *(const uint8_t*)_map[FLAGS].data();};  
    uint32_t checksum() { if (!exists(CHECKSUM)) return 0; return *(const uint16_t*)_map[CHECKSUM].data();};  
    uint32_t window() { if (!exists(RWIN)) return 0; return *(const uint32_t*)_map[RWIN].data();};  
    uint32_t timestamp() { if (!exists(TIMESTAMP)) return 0; return *(const uint32_t*)_map[TIMESTAMP].data();};  
	// TODO: SACK

    //enum { TYPE, PKT_INFO, SRC_XID, DST_XID, SEQ_NUM, ACK_NUM, LENGTH}; 	// Xtransport old header fields
    //enum { SYN=1, SYNACK, DATA, ACK, FIN};	// XSP PKT_INFO (flags)

	enum { TYPE, SEQ_NUM, ACK_NUM, OFFSET, FLAGS, CHECKSUM, RWIN, TIMESTAMP, SACK};	// new header fields (support XTCP) 
	enum { XSOCK_STREAM=1, XSOCK_DGRAM, XSOCK_RAW, XSOCK_CHUNK};	// TYPE (protocol)

	// XTCP flags
	#define	TH_FIN		0x01
	#define	TH_SYN		0x02
	#define	TH_RST		0x04
	#define	TH_PUSH		0x08
	#define	TH_ACK		0x10
	#define	TH_URG		0x20
	#define	TH_ECE		0x40
	#define	TH_CWR		0x80
    
    //enum { OP_REQUEST=1, OP_RESPONSE, OP_LOCAL_PUTCID, OP_REDUNDANT_REQUEST};
};

class TransportHeaderEncap : public XIAGenericExtHeaderEncap { public:

    /* data length contained in the packet*/
    //TransportHeaderEncap(uint16_t offset, uint32_t chunk_offset, uint16_t length, uint32_t chunk_length, char opcode= TransportHeader::OP_RESPONSE);

    //TransportHeaderEncap(char type, char pkt_info, XID src_xid, XID dst_xid, uint32_t seq_num, uint32_t ack_num, uint16_t length);
    //TransportHeaderEncap(char type, char pkt_info, uint32_t seq_num, uint32_t ack_num, uint16_t length);
    TransportHeaderEncap(char type, 
						 uint32_t seq_num, 
						 uint32_t ack_num, 
						 uint8_t offset, 
						 uint8_t flags, 
						 uint16_t checksum, 
						 uint32_t window, 
						 uint32_t timestamp);

    //static TransportHeaderEncap* MakeRequestHeader() { return new TransportHeaderEncap(TransportHeader::OP_REQUEST,0,0); };
    //static TransportHeaderEncap* MakeRPTRequestHeader() { return new TransportHeaderEncap(TransportHeader::OP_REDUNDANT_REQUEST,0,0); };
    
    /*static TransportHeaderEncap* MakeSYNHeader( uint32_t seq_num, uint32_t ack_num, uint16_t length ) 
                        { return new TransportHeaderEncap(TransportHeader::XSOCK_STREAM, TransportHeader::SYN, seq_num, ack_num, length); };

    static TransportHeaderEncap* MakeSYNACKHeader( uint32_t seq_num, uint32_t ack_num, uint16_t length ) 
                        { return new TransportHeaderEncap(TransportHeader::XSOCK_STREAM, TransportHeader::SYNACK, seq_num, ack_num, length); }; 
                        
    static TransportHeaderEncap* MakeDATAHeader( uint32_t seq_num, uint32_t ack_num, uint16_t length ) 
                        { return new TransportHeaderEncap(TransportHeader::XSOCK_STREAM, TransportHeader::DATA, seq_num, ack_num, length); }; 
                            
    static TransportHeaderEncap* MakeACKHeader( uint32_t seq_num, uint32_t ack_num, uint16_t length ) 
                        { return new TransportHeaderEncap(TransportHeader::XSOCK_STREAM, TransportHeader::ACK, seq_num, ack_num, length); };                         
                        
    static TransportHeaderEncap* MakeFINHeader( uint32_t seq_num, uint32_t ack_num, uint16_t length ) 
                        { return new TransportHeaderEncap(TransportHeader::XSOCK_STREAM, TransportHeader::FIN, seq_num, ack_num, length); };     
                                                           
    static TransportHeaderEncap* MakeDGRAMHeader( uint16_t length ) 
                        { return new TransportHeaderEncap(TransportHeader::XSOCK_DGRAM, TransportHeader::DATA, -1, -1, length); }; */
                        
};


CLICK_ENDDECLS
#endif
