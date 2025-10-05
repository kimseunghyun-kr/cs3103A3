// ===================== include/parsed_url.hpp =====================
#pragma once
#include <string>

namespace geo
{
    class ParsedURL
    {
    public:
        std::string scheme; // "http" or "https"
        std::string host;   // e.g., "varlabs.comp.nus.edu.sg"
        std::string path;   // e.g., "/tools/yourip.php"

        explicit ParsedURL(const std::string &url);
        std::string toGetRequestString() const;
    };
} // namespace geo