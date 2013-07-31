// -*- related-file-name: "../include/click/xiatransportheader.hh" -*-
/*
 */

#include <click/config.h>
#include <click/string.hh>
#include <click/glue.hh>
#include <click/xiaextheader.hh>
#include <click/xiatransportheader.hh>
#if CLICK_USERLEVEL
# include <unistd.h>
#endif
CLICK_DECLS

//TransportHeaderEncap::TransportHeaderEncap(char type, char pkt_info, uint32_t seq_num, uint32_t ack_num, uint16_t length) {
TransportHeaderEncap::TransportHeaderEncap(char type, 
										 uint32_t seq_num, 
										 uint32_t ack_num, 
										 uint8_t offset, 
										 uint8_t flags, 
										 uint16_t checksum, 
										 uint32_t window, 
										 uint32_t timestamp) {
    this->map()[TransportHeader::TYPE]= String((const char*)&type, sizeof(type));
    this->map()[TransportHeader::SEQ_NUM]= String((const char*)&seq_num, sizeof(seq_num));
    this->map()[TransportHeader::ACK_NUM]= String((const char*)&ack_num, sizeof(ack_num));        
    this->map()[TransportHeader::OFFSET]= String((const char*)&offset, sizeof(offset));
    this->map()[TransportHeader::FLAGS]= String((const char*)&flags, sizeof(flags));
    this->map()[TransportHeader::CHECKSUM]= String((const char*)&checksum, sizeof(checksum));
    this->map()[TransportHeader::RWIN]= String((const char*)&window, sizeof(window));
    this->map()[TransportHeader::TIMESTAMP]= String((const char*)&timestamp, sizeof(timestamp));
    this->update();
}

/*
TransportHeaderEncap::TransportHeaderEncap(uint8_t opcode, uint32_t chunk_offset, uint16_t length)
{
    this->map()[TransportHeader::CHUNK_OFFSET]= String((const char*)&chunk_offset, sizeof(chunk_offset));
    this->map()[TransportHeader::LENGTH]= String((const char*)&length, sizeof(length));
    this->map()[TransportHeader::OPCODE]= String((const char*)&opcode, sizeof(uint8_t));
    this->update();
}
*/

CLICK_ENDDECLS
