/**
 * @file    threat_engine.cpp
 * @brief   Cloud Security — High-Performance Threat Detection Engine
 * @project Cloud Security & Monitoring Dashboard
 * @author  Manav Gupta | GitHub: ManavGupta0657
 *
 * What this does:
 *   Processes a stream of synthetic cloud security log entries (or real log
 *   files piped in) and detects anomalies using a sliding-window Z-score
 *   algorithm. Classifies each finding by severity, then writes a structured
 *   JSON report that the Python Flask backend reads via /api/engine.
 *
 * Why C++ and not just Python?
 *   Real production log pipelines deal with millions of events per second.
 *   C++ gives us deterministic low-latency processing — the Python layer
 *   handles AWS API calls and HTTP serving, while this engine handles the
 *   heavy number-crunching on raw log data.
 *
 * Compile:
 *   g++ -std=c++17 -O2 -o threat_engine threat_engine.cpp
 *
 * Run (simulation mode — generates synthetic logs):
 *   ./threat_engine --simulate --threshold 3.0 --window 60 --output threats_output.json
 *
 * The JSON output is read by backend.py's /api/engine endpoint.
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <deque>
#include <map>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <ctime>
#include <chrono>
#include <iomanip>
#include <random>
#include <stdexcept>

// ============================================================================
// Data Structures
// ============================================================================

enum class Severity { LOW, MEDIUM, HIGH, CRITICAL };

// Represents one raw log line from a cloud resource
struct LogEntry {
    std::string timestamp;
    std::string source_ip;
    std::string resource;
    std::string event_type;
    double      traffic_gbh;      // inbound traffic GB/h — main anomaly signal
    int         failed_logins;    // brute-force indicator
    int         port_scans;       // reconnaissance indicator
    bool        root_access;      // always escalates severity
    std::string region;
};

// Represents a detected threat after classification
struct ThreatFinding {
    std::string id;
    std::string timestamp;
    std::string event_type;
    std::string source_ip;
    std::string resource;
    std::string region;
    Severity    severity;
    double      anomaly_score;    // Z-score from the detector
    std::string description;
    std::string status;           // Open / Mitigated etc
};

// ============================================================================
// Utility helpers
// ============================================================================

std::string severity_to_string(Severity s) {
    switch (s) {
        case Severity::CRITICAL: return "Critical";
        case Severity::HIGH:     return "High";
        case Severity::MEDIUM:   return "Medium";
        default:                 return "Low";
    }
}

std::string current_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto t   = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

std::string generate_id(int idx) {
    return "eng-" + std::to_string(100000 + idx);
}

// Minimal JSON string escaping
std::string esc(const std::string& s) {
    std::string out;
    for (char c : s) {
        if      (c == '"')  out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else                out += c;
    }
    return out;
}

// ============================================================================
// Sliding-Window Z-Score Anomaly Detector
// ============================================================================

class ZScoreDetector {
public:
    /**
     * @param window_size  Number of recent samples to keep in the rolling window
     * @param threshold    Z-score cutoff above which we flag an anomaly
     *
     * Z-score = |value - mean| / stddev
     * If a new data point is more than `threshold` standard deviations away
     * from the rolling mean, it's flagged as anomalous.
     *
     * Window size of 60 means we compare each new traffic reading against
     * the last 60 readings — roughly the last 60 seconds in a 1-sample/sec stream.
     */
    explicit ZScoreDetector(size_t window_size = 60, double threshold = 3.0)
        : window_(window_size), threshold_(threshold) {}

    double feed(double value) {
        buf_.push_back(value);
        if (buf_.size() > window_)
            buf_.pop_front();

        if (buf_.size() < 2) return 0.0;

        double mean = mean_();
        double sd   = stddev_(mean);
        if (sd < 1e-9) return 0.0;   // avoid div-by-zero on flat traffic

        return std::abs(value - mean) / sd;
    }

    bool is_anomaly(double z) const { return z > threshold_; }
    double threshold()         const { return threshold_; }

private:
    std::deque<double> buf_;
    size_t             window_;
    double             threshold_;

    double mean_() const {
        return std::accumulate(buf_.begin(), buf_.end(), 0.0) / buf_.size();
    }
    double stddev_(double mean) const {
        double sq = 0.0;
        for (double v : buf_) sq += (v - mean) * (v - mean);
        return std::sqrt(sq / buf_.size());
    }
};

// ============================================================================
// Threat Classifier
// ============================================================================

class ThreatClassifier {
public:
    /**
     * Multi-signal classification:
     *   1. Root access → always Critical regardless of everything else
     *   2. High Z-score (traffic anomaly) → Critical or High
     *   3. Brute-force login count → escalates severity
     *   4. Port scan count → at least Medium
     *
     * This mirrors how real SIEM rules work — each signal adds weight.
     */
    static Severity classify(const LogEntry& e, double z) {
        if (e.root_access)          return Severity::CRITICAL;
        if (z > 4.0)                return Severity::CRITICAL;
        if (e.failed_logins > 50)   return Severity::CRITICAL;
        if (z > 3.0)                return Severity::HIGH;
        if (e.failed_logins > 20)   return Severity::HIGH;
        if (e.port_scans > 100)     return Severity::HIGH;
        if (e.failed_logins > 5)    return Severity::MEDIUM;
        if (e.port_scans > 10)      return Severity::MEDIUM;
        if (z > 2.0)                return Severity::MEDIUM;
        return Severity::LOW;
    }

    static std::string describe(const LogEntry& e, Severity sev, double z) {
        std::ostringstream oss;
        if (e.root_access)
            oss << "Root account access detected without MFA from " << e.source_ip << ". ";
        if (e.failed_logins > 5)
            oss << "Brute-force: " << e.failed_logins << " failed logins. ";
        if (e.port_scans > 10)
            oss << "Port scan: " << e.port_scans << " probes. ";
        if (z > 2.5)
            oss << "Traffic anomaly: Z=" << std::fixed << std::setprecision(2)
                << z << " (" << e.traffic_gbh << " GB/h). ";
        if (oss.str().empty())
            oss << "Suspicious activity from " << e.source_ip << " on " << e.resource << ".";
        return oss.str();
    }
};

// ============================================================================
// Log Simulator — generates synthetic cloud log stream
// ============================================================================

class LogSimulator {
public:
    LogSimulator() : rng_(std::random_device{}()) {}

    LogEntry generate(int idx) {
        static const std::vector<std::string> regions = {
            "us-east-1", "eu-west-1", "ap-south-1", "us-west-2", "sa-east-1"
        };
        static const std::vector<std::string> event_types = {
            "SSH_LOGIN", "S3_ACCESS", "IAM_CHANGE", "PORT_SCAN",
            "ROOT_LOGIN", "LAMBDA_INVOKE", "EC2_DESCRIBE", "API_CALL",
        };
        static const std::vector<std::string> resources = {
            "i-0a1b2c3d4e5f", "arn:aws:s3:::prod-data-bucket",
            "arn:aws:iam::123456789:user/admin", "arn:aws:lambda:fn:worker",
            "arn:aws:ec2:i-0f9e8d7c", "arn:aws:rds:db-primary",
        };

        auto pick = [&](const auto& v) -> const std::string& {
            return v[std::uniform_int_distribution<int>(0, (int)v.size()-1)(rng_)];
        };

        // Inject a DDoS spike every ~20 entries (entry 13, 33, 53 …)
        double traffic = (idx % 20 == 13)
            ? std::uniform_real_distribution<double>(10.0, 14.0)(rng_)
            : std::uniform_real_distribution<double>(1.5, 4.5)(rng_);

        std::string ip = "192.168."
            + std::to_string(std::uniform_int_distribution<int>(0, 254)(rng_))
            + "." + std::to_string(std::uniform_int_distribution<int>(1, 254)(rng_));

        return LogEntry{
            .timestamp     = current_timestamp(),
            .source_ip     = ip,
            .resource      = pick(resources),
            .event_type    = pick(event_types),
            .traffic_gbh   = traffic,
            .failed_logins = std::uniform_int_distribution<int>(0, 80)(rng_),
            .port_scans    = std::uniform_int_distribution<int>(0, 200)(rng_),
            .root_access   = std::bernoulli_distribution(0.05)(rng_),  // 5% chance
            .region        = pick(regions),
        };
    }

private:
    std::mt19937 rng_;
};

// ============================================================================
// JSON Report Generator
// ============================================================================

class ReportGenerator {
public:
    static std::string to_json(
        const std::vector<ThreatFinding>& findings,
        const std::map<std::string, int>& counts,
        double threshold, size_t window, int total_processed)
    {
        std::ostringstream j;
        j << "{\n";
        j << "  \"generated_at\": \""  << current_timestamp() << "\",\n";
        j << "  \"engine\": \"C++ ZScore v1.0 (Manav Gupta)\",\n";
        j << "  \"algorithm\": \"sliding-window-zscore\",\n";
        j << "  \"threshold\": "       << std::fixed << std::setprecision(1) << threshold << ",\n";
        j << "  \"window_size\": "     << window << ",\n";
        j << "  \"entries_processed\": " << total_processed << ",\n";
        j << "  \"total\": "           << findings.size() << ",\n";
        j << "  \"counts\": {\n";
        j << "    \"Critical\": " << counts.at("Critical") << ",\n";
        j << "    \"High\": "     << counts.at("High")     << ",\n";
        j << "    \"Medium\": "   << counts.at("Medium")   << ",\n";
        j << "    \"Low\": "      << counts.at("Low")      << "\n";
        j << "  },\n";
        j << "  \"findings\": [\n";

        for (size_t i = 0; i < findings.size(); ++i) {
            const auto& f = findings[i];
            j << "    {\n";
            j << "      \"id\": \""            << esc(f.id)          << "\",\n";
            j << "      \"timestamp\": \""     << esc(f.timestamp)   << "\",\n";
            j << "      \"type\": \""          << esc(f.event_type)  << "\",\n";
            j << "      \"source_ip\": \""     << esc(f.source_ip)   << "\",\n";
            j << "      \"resource\": \""      << esc(f.resource)    << "\",\n";
            j << "      \"region\": \""        << esc(f.region)      << "\",\n";
            j << "      \"severity\": \""      << severity_to_string(f.severity) << "\",\n";
            j << "      \"anomaly_score\": "   << std::fixed << std::setprecision(3) << f.anomaly_score << ",\n";
            j << "      \"description\": \""   << esc(f.description) << "\",\n";
            j << "      \"status\": \""        << esc(f.status)      << "\"\n";
            j << "    }" << (i + 1 < findings.size() ? "," : "") << "\n";
        }

        j << "  ]\n}\n";
        return j.str();
    }
};

// ============================================================================
// main
// ============================================================================

int main(int argc, char* argv[]) {
    bool        simulate    = false;
    double      threshold   = 3.0;
    size_t      window      = 60;
    int         num_entries = 100;
    std::string out_file    = "threats_output.json";

    for (int i = 1; i < argc; ++i) {
        std::string a(argv[i]);
        if      (a == "--simulate")                      simulate    = true;
        else if (a == "--threshold" && i+1 < argc) threshold   = std::stod(argv[++i]);
        else if (a == "--window"    && i+1 < argc) window      = std::stoul(argv[++i]);
        else if (a == "--entries"   && i+1 < argc) num_entries = std::stoi(argv[++i]);
        else if (a == "--output"    && i+1 < argc) out_file    = argv[++i];
    }

    std::cout << "==========================================================\n";
    std::cout << "  Cloud Security Threat Detection Engine v1.0\n";
    std::cout << "  Manav Gupta | Summer Internship 2025\n";
    std::cout << "==========================================================\n";
    std::cout << "  Mode      : " << (simulate ? "SIMULATION" : "LIVE") << "\n";
    std::cout << "  Threshold : " << threshold << " (Z-score)\n";
    std::cout << "  Window    : " << window    << " samples\n";
    std::cout << "  Entries   : " << num_entries << "\n";
    std::cout << "  Output    : " << out_file  << "\n";
    std::cout << "----------------------------------------------------------\n\n";

    ZScoreDetector  detector(window, threshold);
    LogSimulator    sim;

    std::vector<ThreatFinding> findings;
    std::map<std::string, int> counts = {
        {"Critical", 0}, {"High", 0}, {"Medium", 0}, {"Low", 0}
    };

    for (int i = 0; i < num_entries; ++i) {
        LogEntry entry = sim.generate(i);

        double   z   = detector.feed(entry.traffic_gbh);
        Severity sev = ThreatClassifier::classify(entry, z);

        // Skip findings that are Low severity AND not a Z-score anomaly
        // (keeps the output focused on actual threats)
        if (sev == Severity::LOW && !detector.is_anomaly(z)) continue;

        ThreatFinding f;
        f.id            = generate_id((int)findings.size());
        f.timestamp     = entry.timestamp;
        f.event_type    = entry.event_type;
        f.source_ip     = entry.source_ip;
        f.resource      = entry.resource;
        f.region        = entry.region;
        f.severity      = sev;
        f.anomaly_score = z;
        f.description   = ThreatClassifier::describe(entry, sev, z);
        f.status        = "Open";

        std::string sv  = severity_to_string(sev);
        counts[sv]++;
        findings.push_back(f);

        // Print one line per finding so you can see it running
        std::cout << "[" << std::setw(8) << sv << "] "
                  << std::setw(20) << std::left << f.event_type
                  << " | " << entry.source_ip
                  << " | Z=" << std::fixed << std::setprecision(2) << z
                  << " | " << entry.region << "\n";
    }

    // Summary
    std::cout << "\n----------------------------------------------------------\n";
    std::cout << "  SCAN COMPLETE — " << findings.size() << " / " << num_entries << " flagged\n";
    std::cout << "  Critical : " << counts["Critical"] << "\n";
    std::cout << "  High     : " << counts["High"]     << "\n";
    std::cout << "  Medium   : " << counts["Medium"]   << "\n";
    std::cout << "  Low      : " << counts["Low"]      << "\n";
    std::cout << "==========================================================\n\n";

    // Write JSON for Flask to consume via /api/engine
    std::string report = ReportGenerator::to_json(findings, counts, threshold, window, num_entries);
    std::ofstream out(out_file);
    if (!out.is_open()) {
        std::cerr << "[ERROR] Cannot write to " << out_file << "\n";
        return 1;
    }
    out << report;
    out.close();
    std::cout << "[OK] Report written to: " << out_file << "\n";
    std::cout << "     Flask reads this via: GET /api/engine\n";

    return 0;
}
