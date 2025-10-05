#pragma once
/**
 * net_compat.hpp
 * Cross-platform compatibility header for low-level IP/ICMP structs.
 * Normalizes Linux-style names (iphdr, icmphdr, ihl, saddr, etc.) on macOS/BSD.
 */

#include <netinet/in.h>

#ifdef __APPLE__
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

// Aliases for Linux-style types
typedef struct ip iphdr;
typedef struct icmp icmphdr;

// Map Linux field names to BSD equivalents
#define ihl   ip_hl
#define saddr ip_src.s_addr
#define daddr ip_dst.s_addr

// Map ICMP constants
#ifndef ICMP_TIME_EXCEEDED
#define ICMP_TIME_EXCEEDED ICMP_TIMXCEED
#endif

#else
// Linux / others
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#endif
