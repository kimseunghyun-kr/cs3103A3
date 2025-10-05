//// ===================== File: include/geo_resolver.hpp =====================
#pragma once
#include <string>
#include <optional>


namespace geo {
struct GeoInfo {
std::string ip;
std::string city;
std::string country;
double lat{};
double lon{};
// network/ASN enrichment
std::string isp; // ISP name
std::string org; // Organization (if present)
std::string as_text; // e.g., "AS15169 Google LLC"
std::string asn; // e.g., "AS15169"
std::string as_name; // e.g., "GOOGLE"
};


class GeoResolver {
public:
static std::optional<GeoInfo> lookup(const std::string& ip);
};
} // namespace geo