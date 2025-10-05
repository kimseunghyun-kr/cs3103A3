// ===================== File: src/diag_logger.cpp =====================
#include "diag_logger.hpp"
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace geo {

static std::string now_ts() {
    using namespace std::chrono;
    auto t  = system_clock::now();
    auto tt = system_clock::to_time_t(t);
    auto ms = duration_cast<milliseconds>(t.time_since_epoch()) % 1000;

    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &tt);
#else
    localtime_r(&tt, &tm);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << '.'
        << std::setw(3) << std::setfill('0') << ms.count();
    return oss.str();
}

DiagLogger::DiagLogger(const std::string& path) : out_(path, std::ios::app) {
    if (out_.is_open()) out_ << "=== geo_tracer diag start " << now_ts() << " ===\n";
}

DiagLogger::~DiagLogger() {
    if (out_.is_open()) out_ << "=== geo_tracer diag end " << now_ts() << " ===\n";
}

void DiagLogger::log(const std::string& line) {
    if (!out_.is_open()) return;
    out_ << now_ts() << " | " << line << '\n';
    out_.flush();
}

} // namespace geo
