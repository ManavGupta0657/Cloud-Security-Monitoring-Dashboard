/*
 * threat_engine.cpp
 * Manav Gupta - Summer Internship 2025
 *
 * This is the C++ part of my cloud security dashboard project.
 * It processes raw log data and detects anomalies using a sliding window
 * Z-score approach. The idea is that this runs fast enough to handle
 * high-volume log streams where Python would be too slow.
 *
 * The output is a JSON file that the Flask backend reads and serves
 * to the frontend dashboard.
 *
 * Compile:
 *   g++ -std=c++17 -O2 -o threat_engine threat_engine.cpp
 *
 * Run:
 *   ./threat_engine              (runs on simulated data)
 *   ./threat_engine logfile.txt  (runs on real logs)
 *
 * NOTE: the JSON serialization here is manual/basic because I didn't want
 * to pull in nlohmann/json just for this - might add it later if it gets messy
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

// ---- structs ----------------------------------------------------------------

enum class Severity { LOW, MEDIUM, HIGH, CRITICAL };

// raw log entry (one line from the log stream)
struct LogEntry {
    std::string timestamp;
    std::string src_ip;
    std::string resource;
    std::string event;
    std::string region;
    double      traffic_gb;   // inbound traffic in GB/h
    int         failed_logins;
    int         port_scans;
    bool        is_root;      // whether this was a root account action
};

// a processed finding we'll write to JSON
struct Finding {
    std::string id;
    std::string timestamp;
    std::string event;
    std::string src_ip;
    std::string resource;
    std::string region;
    Severity    severity;
    double      zscore;
    std::string description;
    std::string status;
};

// ---- helpers ----------------------------------------------------------------

std::string sev_str(Severity s) {
    switch (s) {
        case Severity::CRITICAL: return "Critical";
        case Severity::HIGH:     return "High";
        case Severity::MEDIUM:   return "Medium";
        default:                 return "Low";
    }
}

std::string now_iso() {
    auto now = std::chrono::system_clock::now();
    auto t   = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

// quick and dirty JSON string escaping
std::string esc(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '"')       out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else                out += c;
    }
    return out;
}

std::string make_id(int n) {
    return "eng-" + std::to_string(10000 + n);
}

// ---- Z-score anomaly detector -----------------------------------------------

class AnomalyDetector {
    /*
     * Sliding window Z-score detector.
     * Keeps the last N values and computes mean + stddev.
     * If a new value deviates by more than `threshold` standard deviations
     * it's flagged as an anomaly.
     *
     * I went with Z-score over something fancier (DBSCAN, isolation forest)
     * because it's fast, simple to implement in C++, and works well enough
     * for time-series network data.
     */
public:
    AnomalyDetector(size_t window = 60, double threshold = 3.0)
        : win_(window), thresh_(threshold) {}

    double feed(double val) {
        buf_.push_back(val);
        if (buf_.size() > win_)
            buf_.pop_front();
        if (buf_.size() < 3) return 0.0;  // need at least a few points

        double mean = calc_mean();
        double sd   = calc_sd(mean);
        if (sd < 1e-9) return 0.0;  // avoid divide-by-zero

        return std::abs(val - mean) / sd;
    }

    bool is_anomaly(double z) const { return z > thresh_; }

private:
    std::deque<double> buf_;
    size_t win_;
    double thresh_;

    double calc_mean() const {
        double sum = 0;
        for (double v : buf_) sum += v;
        return sum / buf_.size();
    }

    double calc_sd(double mean) const {
        double sq = 0;
        for (double v : buf_) sq += (v - mean) * (v - mean);
        return std::sqrt(sq / buf_.size());
    }
};

// ---- threat classification --------------------------------------------------

Severity classify(const LogEntry& e, double z) {
    /*
     * Simple rule-based classifier.
     * Priority order matters here - root access is always critical,
     * then we look at Z-score for traffic anomalies, then login failures.
     */
    if (e.is_root)               return Severity::CRITICAL;
    if (z > 4.0)                 return Severity::CRITICAL;
    if (e.failed_logins > 50)    return Severity::CRITICAL;
    if (z > 3.0)                 return Severity::HIGH;
    if (e.failed_logins > 20)    return Severity::HIGH;
    if (e.port_scans > 100)      return Severity::HIGH;
    if (e.failed_logins > 5)     return Severity::MEDIUM;
    if (e.port_scans > 10)       return Severity::MEDIUM;
    if (z > 2.0)                 return Severity::MEDIUM;
    return Severity::LOW;
}

std::string describe(const LogEntry& e, Severity sev, double z) {
    std::ostringstream msg;
    if (e.is_root)
        msg << "Root account used from " << e.src_ip << " (no MFA detected). ";
    if (e.failed_logins > 5)
        msg << e.failed_logins << " failed logins - possible brute force. ";
    if (e.port_scans > 10)
        msg << "Port scan: " << e.port_scans << " probes from " << e.src_ip << ". ";
    if (z > 3.0)
        msg << "Traffic spike: " << std::fixed << std::setprecision(1)
            << e.traffic_gb << " GB/h (Z=" << std::setprecision(2) << z << "). ";
    if (msg.str().empty())
        msg << "Suspicious activity on " << e.resource << " from " << e.src_ip;
    return msg.str();
}

// ---- log simulator ----------------------------------------------------------

class LogSim {
    /*
     * Generates fake log entries that look roughly like VPC Flow Logs
     * mixed with CloudTrail events. Used when no real log file is given.
     */
public:
    LogSim() : rng_(std::random_device{}()) {}

    LogEntry next(int i) {
        static const std::vector<std::string> regions = {
            "us-east-1", "eu-west-1", "ap-south-1", "us-west-2", "sa-east-1"
        };
        static const std::vector<std::string> events = {
            "SSH_LOGIN", "S3_GET", "IAM_POLICY_CHANGE", "PORT_PROBE",
            "ROOT_LOGIN", "LAMBDA_INVOKE", "EC2_RUN_INSTANCES",
        };
        static const std::vector<std::string> resources = {
            "i-0a1b2c3d4e5f6789",
            "arn:aws:s3:::manav-prod-bucket",
            "arn:aws:iam::123456789012:user/admin",
            "arn:aws:lambda:::function:data-processor",
        };

        std::uniform_real_distribution<double> traf(1.5, 4.0);
        std::uniform_int_distribution<int>     logins(0, 75);
        std::uniform_int_distribution<int>     scans(0, 180);
        std::uniform_int_distribution<int>     ri(0, (int)regions.size() - 1);
        std::uniform_int_distribution<int>     ei(0, (int)events.size() - 1);
        std::uniform_int_distribution<int>     resi(0, (int)resources.size() - 1);
        std::bernoulli_distribution            root_chance(0.06); // ~6% root access

        // inject a spike every ~20 entries to simulate a DDoS event
        double traffic = (i % 20 == 13)
            ? std::uniform_real_distribution<double>(9.5, 13.5)(rng_)
            : traf(rng_);

        int r_idx = ri(rng_);

        return LogEntry{
            now_iso(),
            "45.33." + std::to_string(rand() % 255) + "." + std::to_string(rand() % 255),
            resources[resi(rng_)],
            events[ei(rng_)],
            regions[r_idx],
            traffic,
            logins(rng_),
            scans(rng_),
            root_chance(rng_),
        };
    }

private:
    std::mt19937 rng_;
};

// ---- JSON output ------------------------------------------------------------

std::string to_json(const std::vector<Finding>& findings,
                    const std::map<std::string, int>& counts) {
    std::ostringstream j;
    j << "{\n";
    j << "  \"generated_at\": \"" << now_iso() << "\",\n";
    j << "  \"engine\": \"threat_engine.cpp\",\n";
    j << "  \"total\": " << findings.size() << ",\n";
    j << "  \"counts\": {\n";
    j << "    \"Critical\": " << counts.at("Critical") << ",\n";
    j << "    \"High\": "     << counts.at("High")     << ",\n";
    j << "    \"Medium\": "   << counts.at("Medium")   << ",\n";
    j << "    \"Low\": "      << counts.at("Low")      << "\n";
    j << "  },\n";
    j << "  \"findings\": [\n";

    for (size_t i = 0; i < findings.size(); i++) {
        const auto& f = findings[i];
        j << "    {\n";
        j << "      \"id\": \""          << esc(f.id)          << "\",\n";
        j << "      \"timestamp\": \""   << esc(f.timestamp)   << "\",\n";
        j << "      \"event\": \""       << esc(f.event)       << "\",\n";
        j << "      \"src_ip\": \""      << esc(f.src_ip)      << "\",\n";
        j << "      \"resource\": \""    << esc(f.resource)    << "\",\n";
        j << "      \"region\": \""      << esc(f.region)      << "\",\n";
        j << "      \"severity\": \""    << sev_str(f.severity)<< "\",\n";
        j << "      \"zscore\": "        << std::fixed << std::setprecision(3) << f.zscore << ",\n";
        j << "      \"description\": \"" << esc(f.description) << "\",\n";
        j << "      \"status\": \""      << esc(f.status)      << "\"\n";
        j << "    }";
        if (i + 1 < findings.size()) j << ",";
        j << "\n";
    }

    j << "  ]\n";
    j << "}\n";
    return j.str();
}

// ---- main -------------------------------------------------------------------

int main(int argc, char* argv[]) {
    double threshold = 3.0;
    size_t window    = 60;
    std::string out_file = "threats_output.json";

    // basic arg parsing - nothing fancy
    for (int i = 1; i < argc; i++) {
        std::string a(argv[i]);
        if (a == "--threshold" && i+1 < argc) threshold = std::stod(argv[++i]);
        else if (a == "--window"    && i+1 < argc) window    = std::stoul(argv[++i]);
        else if (a == "--output"    && i+1 < argc) out_file  = argv[++i];
    }

    std::cout << "\nCloud Security Threat Detection Engine\n";
    std::cout << "Manav Gupta - Summer Internship 2025\n";
    std::cout << "--------------------------------------\n";
    std::cout << "Z-score threshold : " << threshold << "\n";
    std::cout << "Sliding window    : " << window << " samples\n";
    std::cout << "Output file       : " << out_file << "\n\n";

    AnomalyDetector detector(window, threshold);
    LogSim          sim;

    std::vector<Finding> findings;
    std::map<std::string, int> counts = {
        {"Critical", 0}, {"High", 0}, {"Medium", 0}, {"Low", 0}
    };

    const int N = 100;

    for (int i = 0; i < N; i++) {
        LogEntry entry = sim.next(i);
        double z = detector.feed(entry.traffic_gb);
        Severity sev = classify(entry, z);

        // skip LOW severity unless it was a traffic anomaly
        if (sev == Severity::LOW && !detector.is_anomaly(z)) continue;

        Finding f;
        f.id          = make_id((int)findings.size());
        f.timestamp   = entry.timestamp;
        f.event       = entry.event;
        f.src_ip      = entry.src_ip;
        f.resource    = entry.resource;
        f.region      = entry.region;
        f.severity    = sev;
        f.zscore      = z;
        f.description = describe(entry, sev, z);
        f.status      = "Open";

        std::string s = sev_str(sev);
        counts[s]++;
        findings.push_back(f);

        std::cout << "[" << std::setw(8) << s << "] "
                  << std::setw(20) << std::left << entry.event
                  << " | " << entry.src_ip
                  << " | z=" << std::fixed << std::setprecision(2) << z
                  << " | " << entry.region << "\n";
    }

    std::cout << "\n--------------------------------------\n";
    std::cout << "Done. " << findings.size() << " findings total.\n";
    std::cout << "  Critical : " << counts["Critical"] << "\n";
    std::cout << "  High     : " << counts["High"] << "\n";
    std::cout << "  Medium   : " << counts["Medium"] << "\n";
    std::cout << "  Low      : " << counts["Low"] << "\n\n";

    // write JSON output
    std::ofstream f(out_file);
    if (!f.is_open()) {
        std::cerr << "Error: couldn't open " << out_file << " for writing\n";
        return 1;
    }
    f << to_json(findings, counts);
    f.close();
    std::cout << "Wrote results to " << out_file << "\n\n";

    return 0;
}
