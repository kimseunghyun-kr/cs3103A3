#pragma once
/**
 * net_compat.hpp
 * Cross-platform compatibility header for low-level IP/ICMP structs.
 * Provides Linux-style names (`iphdr`, `icmphdr`) on macOS/BSD.
 */

#ifdef __APPLE__
// macOS / BSD
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
typedef struct ip iphdr;
typedef struct icmp icmphdr;
#else
// Linux / others
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#endif
