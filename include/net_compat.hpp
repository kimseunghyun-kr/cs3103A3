#pragma once
/**
 * net_compat.hpp
 * Cross-platform compatibility header for raw IP/ICMP/TCP access.
 * Normalizes Linux-style struct and field names on macOS/BSD so that code
 * written for Linux's <netinet/ip.h>, <netinet/ip_icmp.h>, and <netinet/tcp.h>
 * compiles and runs on macOS without source changes elsewhere.
 */

#include <netinet/in.h>

#ifdef __APPLE__
// -----------------------------
// macOS / BSD
// -----------------------------
#  include <netinet/in_systm.h>  // required before <netinet/ip.h> on BSD
#  include <netinet/ip.h>        // struct ip
#  include <netinet/ip_icmp.h>   // struct icmp
#  include <netinet/tcp.h>       // struct tcphdr

// Type aliases so user code can keep using Linux names.
using iphdr  = struct ip;
using icmphdr = struct icmp;
using tcphdr = struct tcphdr;

// Map Linux iphdr field names to BSD struct ip names.
#  define ihl         ip_hl
#  define version     ip_v
#  define tos         ip_tos
#  define tot_len     ip_len
#  define id          ip_id
#  define frag_off    ip_off
#  define ttl         ip_ttl
#  define protocol    ip_p
#  define check       ip_sum
// saddr/daddr are u32 on Linux; map to in_addr.s_addr on BSD.
#  define saddr       ip_src.s_addr
#  define daddr       ip_dst.s_addr

// Map common Linux tcphdr field names to BSD names (lvalues).
#  define source      th_sport
#  define dest        th_dport
#  define seq         th_seq
#  define ack_seq     th_ack
#  define doff        th_off
#  define window      th_win
#  define check       th_sum
#  define urg_ptr     th_urp

// --- TCP flag helpers ---
// On Linux, tcphdr has bitfields: syn/ack/rst. On BSD, flags live in th_flags.
// Provide portable setters/getters so call sites can use the same names.
inline void tcp_set_syn(tcphdr* t, int on){ if(on) t->th_flags |= TH_SYN; else t->th_flags &= ~TH_SYN; }
inline void tcp_set_ack(tcphdr* t, int on){ if(on) t->th_flags |= TH_ACK; else t->th_flags &= ~TH_ACK; }
inline void tcp_set_rst(tcphdr* t, int on){ if(on) t->th_flags |= TH_RST; else t->th_flags &= ~TH_RST; }
inline bool tcp_is_syn(const tcphdr* t){ return (t->th_flags & TH_SYN) != 0; }
inline bool tcp_is_ack(const tcphdr* t){ return (t->th_flags & TH_ACK) != 0; }
inline bool tcp_is_rst(const tcphdr* t){ return (t->th_flags & TH_RST) != 0; }

#  define TCP_SET_SYN(t,v) tcp_set_syn((t),(v))
#  define TCP_SET_ACK(t,v) tcp_set_ack((t),(v))
#  define TCP_SET_RST(t,v) tcp_set_rst((t),(v))
#  define TCP_IS_SYN(t)    tcp_is_syn((t))
#  define TCP_IS_ACK(t)    tcp_is_ack((t))
#  define TCP_IS_RST(t)    tcp_is_rst((t))

// Map Linux icmphdr field names to BSD names.
#  define type       icmp_type
#  define code       icmp_code

#else
// -----------------------------
// Linux / others
// -----------------------------
#  include <netinet/ip.h>       // struct iphdr
#  include <netinet/ip_icmp.h>  // struct icmphdr
#  include <netinet/tcp.h>      // struct tcphdr

// On Linux, direct bitfields exist; provide no-op helpers/macros so callers
// can write portable code without #ifdefs.
inline void tcp_set_syn(tcphdr* t, int on){ t->syn = on; }
inline void tcp_set_ack(tcphdr* t, int on){ t->ack = on; }
inline void tcp_set_rst(tcphdr* t, int on){ t->rst = on; }
inline bool tcp_is_syn(const tcphdr* t){ return t->syn; }
inline bool tcp_is_ack(const tcphdr* t){ return t->ack; }
inline bool tcp_is_rst(const tcphdr* t){ return t->rst; }

#  define TCP_SET_SYN(t,v) tcp_set_syn((t),(v))
#  define TCP_SET_ACK(t,v) tcp_set_ack((t),(v))
#  define TCP_SET_RST(t,v) tcp_set_rst((t),(v))
#  define TCP_IS_SYN(t)    tcp_is_syn((t))
#  define TCP_IS_ACK(t)    tcp_is_ack((t))
#  define TCP_IS_RST(t)    tcp_is_rst((t))

#endif
