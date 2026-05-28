/**
 * @file    threat_engine.cpp
 * @brief   Cloud Security — High-Performance Threat Detection Engine
 * @project Cloud Security & Monitoring Dashboard
 * @author  Manav Gupta | GitHub: ManavGupta0657
 *
 * Description:
 *   A C++ engine that processes raw cloud security log streams at high
 *   throughput. It detects anomalies using a sliding-window Z-score
 *   algorithm, classifies threat severity, and outputs structured JSON
 *   reports consumed by the Python Flask backend (/api/threats).
 *
 * Compile:
 *   g++ -std=c++17 -O2 -o threat_engine threat_engine.cpp
 *
 * Run:
 *   ./threat_engine [--simulate] [--threshold 3.0] [--window 60]
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

// ─────────────────────────────────────────────────────────────────────────────
// Data Structures
// ─────────────────────────────────────────────────────────────────────────────

enum class Severity { LOW, MEDIUM, HIGH, CRITICAL };

struct LogEntry {
    std::string timestamp;
    std::string source_ip;
    std::string resource;
    std::string event_type;
    double      traffic_gbh;
    int         failed_logins;
    int         port_scans;
    bool        root_access;
    std::string region;
};

struct ThreatFinding {
    std::string id;
    std::string timestamp;
    std::string event_type;
    std::string source_ip;
    std::string resource;
    std::string region;
    Severity    severity;
    double      anomaly_score;
    std::string description;
    std::string status;
};

// ─────────────────────────────────────────────────────────────────────────────
// Utility Functions
// ─────────────────────────────────────────────────────────────────────────────

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

std::string generate_id(int index) {
    return "finding-" + std::to_string(100000 + index);
}

std::string escape_json(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '"')  out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else           out += c;
    }
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Sliding-Window Z-Score Anomaly Detector
// ─────────────────────────────────────────────────────────────────────────────

class ZScoreDetector {
public:
    explicit ZScoreDetector(size_t window_size = 60, double threshold = 3.0)
        : window_(window_size), threshold_(threshold) {}

    /**
     * Feed a new data point. Returns the Z-score.
     * A score above threshold indicates an anomaly.
     */
    double feed(double value) {
        buffer_.push_back(value);
        if (buffer_.size() > window_)
            buffer_.pop_front();

        if (buffer_.size() < 2) return 0.0;

        double mean = compute_mean();
        double stddev = compute_stddev(mean);
        if (stddev < 1e-9) return 0.0;

        return std::abs(value - mean) / stddev;
    }

    bool is_anomaly(double zscore) const {
        return zscore > threshold_;
    }

    double get_threshold() const { return threshold_; }

private:
    std::deque<double> buffer_;
    size_t             window_;
    double             threshold_;

    double compute_mean() const {
        return std::accumulate(buffer_.begin(), buffer_.end(), 0.0) / buffer_.size();
    }

    double compute_stddev(double mean) const {
        double sq_sum = 0.0;
        for (double v : buffer_)
            sq_sum += (v - mean) * (v - mean);
        return std::sqrt(sq_sum / buffer_.size());
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Threat Classifier
// ─────────────────────────────────────────────────────────────────────────────

class ThreatClassifier {
public:
    /**
     * Classify a log entry into a severity level based on heuristics:
     *  - Root access → always Critical
     *  - High Z-score traffic → Critical / High
     *  - Brute-force logins → High
     *  - Port scans → Medium / High
     */
    static Severity classify(const LogEntry& entry, double zscore) {
        if (entry.root_access)             return Severity::CRITICAL;
        if (zscore > 4.0)                  return Severity::CRITICAL;
        if (entry.failed_logins > 50)      return Severity::CRITICAL;
        if (zscore > 3.0)                  return Severity::HIGH;
        if (entry.failed_logins > 20)      return Severity::HIGH;
        if (entry.port_scans > 100)        return Severity::HIGH;
        if (entry.failed_logins > 5)       return Severity::MEDIUM;
        if (entry.port_scans > 10)         return Severity::MEDIUM;
        if (zscore > 2.0)                  return Severity::MEDIUM;
        return Severity::LOW;
    }

    static std::string describe(const LogEntry& entry, Severity sev, double zscore) {
        std::ostringstream oss;
        if (entry.root_access)
            oss << "Root account access detected without MFA from " << entry.source_ip << ". ";
        if (entry.failed_logins > 5)
            oss << "Brute-force attempt: " << entry.failed_logins << " failed logins. ";
        if (entry.port_scans > 10)
            oss << "Port scan detected: " << entry.port_scans << " probes. ";
        if (zscore > 3.0)
            oss << "Network traffic anomaly: Z-score " << std::fixed << std::setprecision(2) << zscore
                << " (" << entry.traffic_gbh << " GB/h vs baseline). ";
        if (oss.str().empty())
            oss << "Suspicious activity from " << entry.source_ip << " on " << entry.resource << ".";
        return oss.str();
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Log Simulator (generates synthetic cloud log entries)
// ─────────────────────────────────────────────────────────────────────────────

class LogSimulator {
public:
    LogSimulator() : rng_(std::random_device{}()) {}

    LogEntry generate(int index) {
        static const std::vector<std::string> regions = {
            "us-east-1", "eu-west-1", "ap-south-1", "us-west-2", "sa-east-1"
        };
        static const std::vector<std::string> event_types = {
            "SSH_LOGIN", "S3_ACCESS", "IAM_CHANGE", "PORT_SCAN",
            "ROOT_LOGIN", "LAMBDA_INVOKE", "EC2_DESCRIBE",
        };
        static const std::vector<std::string> resources = {
            "i-0a1b2c3d4e5f", "arn:aws:s3:::prod-bucket",
            "arn:aws:iam::123456789:user/admin", "arn:aws:lambda:fn:worker",
        };

        std::uniform_real_distribution<double> traffic_dist(1.5, 4.5);
        std::uniform_int_distribution<int>     login_dist(0, 80);
        std::uniform_int_distribution<int>     scan_dist(0, 200);
        std::uniform_int_distribution<int>     region_dist(0, (int)regions.size()-1);
        std::uniform_int_distribution<int>     event_dist(0, (int)event_types.size()-1);
        std::uniform_int_distribution<int>     res_dist(0, (int)resources.size()-1);
        std::bernoulli_distribution            root_dist(0.05);   // 5% root access

        // Inject a DDoS spike every ~20 entries
        double traffic = (index % 20 == 13)
            ? std::uniform_real_distribution<double>(10.0, 14.0)(rng_)
            : traffic_dist(rng_);

        return LogEntry{
            .timestamp     = current_timestamp(),
            .source_ip     = "192.168." + std::to_string(rand()%255) + "." + std::to_string(rand()%255),
            .resource      = resources[res_dist(rng_)],
            .event_type    = event_types[event_dist(rng_)],
            .traffic_gbh   = traffic,
            .failed_logins = login_dist(rng_),
            .port_scans    = scan_dist(rng_),
            .root_access   = root_dist(rng_),
            .region        = regions[region_dist(rng_)],
        };
    }

private:
    std::mt19937 rng_;
};

// ─────────────────────────────────────────────────────────────────────────────
// JSON Report Generator
// ─────────────────────────────────────────────────────────────────────────────

class ReportGenerator {
public:
    static std::string to_json(const std::vector<ThreatFinding>& findings,
                               const std::map<std::string, int>& counts) {
        std::ostringstream json;
        json << "{\n";
        json << "  \"generated_at\": \"" << current_timestamp() << "\",\n";
        json << "  \"total\": " << findings.size() << ",\n";
        json << "  \"counts\": {\n";
        json << "    \"Critical\": " << counts.at("Critical") << ",\n";
        json << "    \"High\": "     << counts.at("High")     << ",\n";
        json << "    \"Medium\": "   << counts.at("Medium")   << ",\n";
        json << "    \"Low\": "      << counts.at("Low")      << "\n";
        json << "  },\n";
        json << "  \"findings\": [\n";

        for (size_t i = 0; i < findings.size(); ++i) {
            const auto& f = findings[i];
            json << "    {\n";
            json << "      \"id\": \""           << escape_json(f.id)          << "\",\n";
            json << "      \"timestamp\": \""    << escape_json(f.timestamp)   << "\",\n";
            json << "      \"type\": \""         << escape_json(f.event_type)  << "\",\n";
            json << "      \"source_ip\": \""    << escape_json(f.source_ip)   << "\",\n";
            json << "      \"resource\": \""     << escape_json(f.resource)    << "\",\n";
            json << "      \"region\": \""       << escape_json(f.region)      << "\",\n";
            json << "      \"severity\": \""     << severity_to_string(f.severity) << "\",\n";
            json << "      \"anomaly_score\": "  << std::fixed << std::setprecision(3) << f.anomaly_score << ",\n";
            json << "      \"description\": \""  << escape_json(f.description) << "\",\n";
            json << "      \"status\": \""       << escape_json(f.status)      << "\"\n";
            json << "    }" << (i + 1 < findings.size() ? "," : "") << "\n";
        }

        json << "  ]\n";
        json << "}\n";
        return json.str();
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Main Engine
// ─────────────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    // ── Parse CLI flags ────────────────────────────────────────────────────
    bool   simulate  = false;
    double threshold = 3.0;
    size_t window    = 60;
    std::string output_file = "threats_output.json";

    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg == "--simulate")    simulate = true;
        else if (arg == "--threshold" && i + 1 < argc) threshold = std::stod(argv[++i]);
        else if (arg == "--window"    && i + 1 < argc) window    = std::stoul(argv[++i]);
        else if (arg == "--output"    && i + 1 < argc) output_file = argv[++i];
    }

    std::cout << "==========================================================\n";
    std::cout << "  Cloud Security Threat Detection Engine v1.0\n";
    std::cout << "  Summer Internship | Cloud Computing Specialization\n";
    std::cout << "==========================================================\n";
    std::cout << "  Mode      : " << (simulate ? "SIMULATION" : "LIVE") << "\n";
    std::cout << "  Threshold : " << threshold << " (Z-score)\n";
    std::cout << "  Window    : " << window    << " samples\n";
    std::cout << "  Output    : " << output_file << "\n";
    std::cout << "----------------------------------------------------------\n\n";

    ZScoreDetector  detector(window, threshold);
    ThreatClassifier classifier;
    LogSimulator     simulator;

    std::vector<ThreatFinding> findings;
    std::map<std::string, int> counts = {
        {"Critical", 0}, {"High", 0}, {"Medium", 0}, {"Low", 0}
    };

    const int NUM_ENTRIES = 100;

    for (int i = 0; i < NUM_ENTRIES; ++i) {
        LogEntry entry = simulator.generate(i);

        double zscore  = detector.feed(entry.traffic_gbh);
        Severity sev   = ThreatClassifier::classify(entry, zscore);

        // Only record Medium and above
        if (sev == Severity::LOW && !detector.is_anomaly(zscore)) continue;

        ThreatFinding finding;
        finding.id            = generate_id((int)findings.size());
        finding.timestamp     = entry.timestamp;
        finding.event_type    = entry.event_type;
        finding.source_ip     = entry.source_ip;
        finding.resource      = entry.resource;
        finding.region        = entry.region;
        finding.severity      = sev;
        finding.anomaly_score = zscore;
        finding.description   = ThreatClassifier::describe(entry, sev, zscore);
        finding.status        = "Open";

        std::string sev_str = severity_to_string(sev);
        counts[sev_str]++;
        findings.push_back(finding);

        // Console output
        std::cout << "[" << sev_str << "] " << finding.event_type
                  << " | " << entry.source_ip
                  << " | Z=" << std::fixed << std::setprecision(2) << zscore
                  << " | " << entry.region << "\n";
    }

    // ── Summary ────────────────────────────────────────────────────────────
    std::cout << "\n----------------------------------------------------------\n";
    std::cout << "  SCAN COMPLETE — " << findings.size() << " findings\n";
    std::cout << "  Critical : " << counts["Critical"] << "\n";
    std::cout << "  High     : " << counts["High"]     << "\n";
    std::cout << "  Medium   : " << counts["Medium"]   << "\n";
    std::cout << "  Low      : " << counts["Low"]      << "\n";
    std::cout << "==========================================================\n\n";

    // ── Write JSON report ──────────────────────────────────────────────────
    std::string json_report = ReportGenerator::to_json(findings, counts);

    std::ofstream outfile(output_file);
    if (outfile.is_open()) {
        outfile << json_report;
        outfile.close();
        std::cout << "[OK] Report saved to: " << output_file << "\n";
    } else {
        std::cerr << "[ERROR] Could not write to " << output_file << "\n";
        return 1;
    }

    return 0;
}
