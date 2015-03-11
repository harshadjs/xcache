// -*- related-file-name: "../../lib/ipflowid.cc" -*-
#ifndef CLICK_IPFLOWID_HH
#define CLICK_IPFLOWID_HH
#include <click/ipaddress.hh>
#include <click/hashcode.hh>
#include <click/xid.hh>
CLICK_DECLS
class Packet;

class XIPFlowID { public:

    struct uninitialized_t {
    };


    /** @brief Construct an empty flow ID.
     *
     * The empty flow ID has zero-valued addresses and ports. */
    XIPFlowID()
	: _saddr(NULL), _daddr(NULL), _sport(0), _dport(0) {
    }

    /** @brief Construct a flow ID with the given parts.
     * @param saddr source address
     * @param sport source port, in network order
     * @param daddr destination address
     * @param dport destination port, in network order */
    XIPFlowID(XID saddr, uint16_t sport, XID daddr, uint16_t dport)
	: _saddr(saddr), _daddr(daddr), _sport(sport), _dport(dport) {
    }

    /** @brief Construct a flow ID from @a p's ip_header() and udp_header().
     * @param p input packet
     * @param reverse if true, use the reverse of @a p's flow ID
     *
     * @pre @a p's ip_header() must point to a first-fragment IPv4 header, and
     * @a p's transport header should have source and destination ports in the
     * UDP-like positions; TCP, UDP, and DCCP fit the bill. */
    // explicit XIPFlowID(const Packet *p, bool reverse = false);

    /** @brief Construct a flow ID from @a iph and the following TCP/UDP header.
     * @param iph IP header
     * @param reverse if true, use the reverse of @a p's flow ID
     *
     * The IP header's header length, @a iph->ip_hl, is used to find the
     * following transport header.  This transport header should have source
     * and destination ports in the UDP-like positions; TCP, UDP, and DCCP fit
     * the bill. */
    // explicit XIPFlowID(const click_ip *iph, bool reverse = false);

    /** @brief Construct an uninitialized flow ID. */
    // inline XIPFlowID(const uninitialized_t &unused) {
	// (void) unused;
    // }


    // typedef XID (XIPFlowID::*unspecified_bool_type)() const;
    /** @brief Return true iff the addresses of this flow ID are zero. */
 //    operator unspecified_bool_type() const {
	// return _saddr || _daddr ? &XIPFlowID::saddr : 0;
 //    }


    /** @brief Return this flow's source address. */
    XID saddr() const {
	return _saddr;
    }
    /** @brief Return this flow's source port, in network order. */
    uint16_t sport() const {
	return _sport;
    }
    /** @brief Return this flow's destination address. */
    XID daddr() const {
	return _daddr;
    }
    /** @brief Return this flow's destination port, in network order. */
    uint16_t dport() const {
	return _dport;
    }

    /** @brief Set this flow's source address to @a a. */
    void set_saddr(XID a) {
	_saddr = a;
    }
    /** @brief Set this flow's source port to @a p.
     * @note @a p should be in network order. */
    void set_sport(uint16_t p) {
	_sport = p;
    }
    /** @brief Set this flow's destination address to @a a. */
    void set_daddr(XID a) {
	_daddr = a;
    }
    /** @brief Set this flow's destination port to @a p.
     * @note @a p should be in network order. */
    void set_dport(uint16_t p) {
	_dport = p;
    }


    /** @brief Set this flow to the given value.
     * @param saddr source address
     * @param sport source port, in network order
     * @param daddr destination address
     * @param dport destination port, in network order */
    void assign(XID saddr, uint16_t sport, XID daddr, uint16_t dport) {
	_saddr = saddr;
	_daddr = daddr;
	_sport = sport;
	_dport = dport;
    }

    XIPFlowID reverse() const {
        return XIPFlowID(_daddr, _dport, _saddr, _sport);
    }
    /** @brief Return this flow's reverse, which swaps sources and destinations.
     * @return XIPFlowID(daddr(), dport(), saddr(), sport()) */
 //    XIPFlowID reverse() const {
	// return XIPFlowID(_daddr, _dport, _saddr, _sport);
 //    }
 //    inline XIPFlowID rev() const CLICK_DEPRECATED;

    /** @brief Hash function.
     * @return The hash value of this XIPFlowID.
     *
     * Equal XIPFlowID objects always have equal hashcode() values. */
    inline hashcode_t hashcode() const;

    /** @brief Unparse this address into a String.
     *
     * Returns a string with formatted like "(SADDR, SPORT, DADDR, DPORT)". */
    // String unparse() const;

    // inline operator String() const CLICK_DEPRECATED;
    // inline String s() const CLICK_DEPRECATED;

  protected:

    // note: several functions depend on this field order!
    XID _saddr;
    XID _daddr;
    uint16_t _sport;			// network byte order
    uint16_t _dport;			// network byte order

    // int unparse(char *s) const;
    // friend StringAccum &operator<<(StringAccum &sa, const XIPFlowID &flow_id);

};


// inline XIPFlowID XIPFlowID::rev() const
// {
//     return reverse();
// }


#define ROT(v, r) ((v)<<(r) | ((unsigned)(v))>>(32-(r)))

inline hashcode_t XIPFlowID::hashcode() const
{
    // more complicated hashcode, but causes less collision
    uint16_t s = ntohs(sport());
    uint16_t d = ntohs(dport());
    uint32_t sx = saddr().hashcode();
    uint32_t dx = daddr().hashcode();
    return (hashcode)(ROT(sx, s%16)
	    ^ ROT(dx, 31-d%16))
	^ ((d << 16) | s);
}

#undef ROT

inline bool operator==(const XIPFlowID &a, const XIPFlowID &b)
{
    return a.sport() == b.sport() && a.dport() == b.dport()
	&& a.saddr() == b.saddr() && a.daddr() == b.daddr();
}

inline bool operator!=(const XIPFlowID &a, const XIPFlowID &b)
{
    return a.sport() != b.sport() || a.dport() != b.dport()
	|| a.saddr() != b.saddr() || a.daddr() != b.daddr();
}

StringAccum &operator<<(StringAccum &, const XIPFlowID &);

// inline XIPFlowID::operator String() const
// {
//     return unparse();
// }

// inline String XIPFlowID::s() const
// {
//     return unparse();
// }

CLICK_ENDDECLS
#endif
