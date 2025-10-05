// ===================== include/geo_resolver.hpp (stub) =====================
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
};


class GeoResolver {
public:
static std::optional<GeoInfo> lookup(const std::string& ip);
};
} // namespace geo