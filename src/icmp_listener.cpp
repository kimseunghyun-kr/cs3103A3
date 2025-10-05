// ===================== src/icmp_listener.cpp (stub) =====================
#include "icmp_listener.hpp"


namespace geo {
bool IcmpListener::open() { return false; }
void IcmpListener::close() {}
std::optional<IcmpPacketInfo> IcmpListener::recv_one(int) { return std::nullopt; }
} // namespace geo