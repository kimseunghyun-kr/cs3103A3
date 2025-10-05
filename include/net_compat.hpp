#pragma once
/**
 * net_compat.hpp
 * Cross-platform compatibility header for raw IP/ICMP/TCP access.
 * Normalizes Linux-style struct and field names on macOS/BSD.
 */

#include <netinet/in.h>

#ifdef __APPLE__
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>

// -----------------------------
// Type aliases
// -----------------------------
typedef struct ip   iphdr;
typedef struct icmp icmphdr;

// -----------------------------
// IP field aliases (scoped accessors)
// -----------------------------
#define IPH(x)   reinterpret_cast<iphdr*>(x)
#define TCPH(x)  reinterpret_cast<tcphdr*>(x)
#define ICMH(x)  reinterpret_cast<icmphdr*>(x)

#define ip_ihl(ip)        ((ip)->ip_hl)
#define ip_version(ip)    ((ip)->ip_v)
#define ip_tos(ip)        ((ip)->ip_tos)
#define ip_tot_len(ip)    ((ip)->ip_len)
#define ip_id(ip)         ((ip)->ip_id)
#define ip_frag_off(ip)   ((ip)->ip_off)
#define ip_ttl(ip)        ((ip)->ip_ttl)
#define ip_protocol(ip)   ((ip)->ip_p)
#define ip_check(ip)      ((ip)->ip_sum)
#define ip_saddr(ip)      ((ip)->ip_src.s_addr)
#define ip_daddr(ip)      ((ip)->ip_dst.s_addr)

// -----------------------------
// TCP field aliases
// -----------------------------
#define tcp_source(t)     ((t)->th_sport)
#define tcp_dest(t)       ((t)->th_dport)
#define tcp_seq(t)        ((t)->th_seq)
#define tcp_ack_seq(t)    ((t)->th_ack)
#define tcp_doff(t)       ((t)->th_off)
#define tcp_window(t)     ((t)->th_win)
#define tcp_check(t)      ((t)->th_sum)
#define tcp_urg_ptr(t)    ((t)->th_urp)
#define tcp_flags(t)      ((t)->th_flags)

// Emulate Linux bitfields (syn/ack/rst)
#define tcp_syn(t)        (((t)->th_flags & TH_SYN) ? 1 : 0)
#define tcp_ack(t)        (((t)->th_flags & TH_ACK) ? 1 : 0)
#define tcp_rst(t)        (((t)->th_flags & TH_RST) ? 1 : 0)

// -----------------------------
// ICMP field aliases
// -----------------------------
#define icmp_type(i)      ((i)->icmp_type)
#define icmp_code(i)      ((i)->icmp_code)
#ifndef ICMP_TIME_EXCEEDED
#define ICMP_TIME_EXCEEDED ICMP_TIMXCEED
#endif

// -----------------------------
// Backward-compatibility aliases (Linux-style names)
// -----------------------------
#define ihl       ip_hl
#define version   ip_v
#define tos       ip_tos
#define tot_len   ip_len
#define id        ip_id
#define frag_off  ip_off
// (no 'ttl' macro! avoid leaking into user structs)
#define protocol  ip_p
#define saddr     ip_src.s_addr
#define daddr     ip_dst.s_addr

#define source    th_sport
#define dest      th_dport
#define seq       th_seq
#define ack_seq   th_ack
#define doff      th_off
#define window    th_win
#define urg_ptr   th_urp
#define syn       tcp_syn(t)
#define ack       tcp_ack(t)
#define rst       tcp_rst(t)

#define type      icmp_type
#define code      icmp_code

#else
// -----------------------------
// Linux / others
// -----------------------------
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#endif
