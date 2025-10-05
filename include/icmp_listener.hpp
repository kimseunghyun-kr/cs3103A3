
//// ===================== File: include/icmp_listener.hpp =====================
#pragma once
#include <optional>
#include <string>

namespace geo
{
    class IcmpListener
    {
    public:
        struct TimeExceeded
        {
            std::string from_ip; // router that sent ICMP
            uint16_t orig_sport; // source port of our original TCP probe
            int orig_ttl;        // TTL of the dropped probe (best-effort)
        };

        bool open();
        void close();
        int fd() const { return fd_; }

        // Call after select() signals readability on fd(). Returns parsed Time Exceeded if any.
        std::optional<TimeExceeded> recv_time_exceeded();

    private:
        int fd_ = -1;
    };
} // namespace geo