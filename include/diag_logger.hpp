// ===================== File: include/diag_logger.hpp =====================
#pragma once
#include <fstream>
#include <string>

namespace geo {

class DiagLogger {
public:
    explicit DiagLogger(const std::string& path);
    ~DiagLogger();

    bool ok() const { return out_.is_open(); }
    void log(const std::string& line);

private:
    std::ofstream out_;
};

} // namespace geo
