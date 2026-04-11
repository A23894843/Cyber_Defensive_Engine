#include <pcap.h>
#include <string>
#include <arpa/inet.h>
#include <map>
#include <ctime>
#include <fcntl.h>
#include <unistd.h>
#include <fstream>
using namespace std;

// Output strictly to a log file instead of stdout/stderr or pipes
ofstream logFile("/home/abhinandan-kali/Desktop/Cyber_Defensive_Engine/Cyber_Defensive_Engine.log", ios::app);
int pipe_fd;

void openPipe() {
    pipe_fd = open("/home/abhinandan-kali/Desktop/Cyber_Defensive_Engine/packet_pipe", O_WRONLY);

    if (pipe_fd == -1)  {
        perror("Pipe open failed");
        exit(1);
    }
}

void sendToPipe(string ip, int pkt, int bytes)  {
    string data = ip + "," + to_string(pkt) + "," + to_string(bytes) + "\n";
    write(pipe_fd, data.c_str(), data.size());
}

void writeLog(const string& message) {
    if (logFile.is_open()) {
        time_t now = time(0);
        char* dt = ctime(&now);
        string timestamp(dt);
        timestamp.pop_back(); // Remove trailing newline from ctime

        logFile << "[" << timestamp << "] " << message << "\n";
        logFile.flush(); // Flush immediately so we don't lose data if it crashes
    }
}

// ---------------- IP HEADER ----------------
class IPHeader {
    const u_char* data;

public:
    // Assumes packet pointer is ALREADY offset past the 14-byte Ethernet header
    IPHeader(const u_char* network_packet) {
        data = network_packet;
    }

    string getSourceIP() const {
        char buffer[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, data + 12, buffer, INET_ADDRSTRLEN);
        return string(buffer);
    }

    string getDestIP() const {
        char buffer[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, data + 16, buffer, INET_ADDRSTRLEN);
        return string(buffer);
    }
};

// ---------------- PACKET ----------------
class Packet {
    const u_char* rawData;
    int capLength;

public:
    Packet(const u_char* packet, int len) {
        rawData = packet;
        capLength = len; // Using caplen for safety
    }

    int getSize() const {
        return capLength;
    }
    
    const u_char* getRaw() const {
        return rawData;
    }
};

// ---------------- SNIFFER ----------------
class PacketSniffer {
    map<string, int> packet_count;
    map<string, int> byte_count;
    time_t last_time;
    pcap_t* handle;
    string device;

public:
    PacketSniffer(const string& dev) {
        device = dev;
        last_time = time(0);
        handle = NULL;
    }

    bool init() {
        char errbuf[PCAP_ERRBUF_SIZE];

        handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);

        if (!handle) {
            writeLog("ERROR: Failed to open device: " + string(errbuf));
            return false;
        }

        writeLog("SUCCESS: Sniffing started on device: " + device);
        return true;
    }

    static void callback(u_char* user,
                         const pcap_pkthdr* header,
                         const u_char* packet) {

        PacketSniffer* sniffer = reinterpret_cast<PacketSniffer*>(user);
        sniffer->process(Packet(packet, header->caplen));
    }

    void process(const Packet& pkt) {
        int size = pkt.getSize();
        const u_char* raw = pkt.getRaw();

        // 1. Ensure packet is large enough to contain Ethernet (14) + Min IPv4 (20) headers
        if (size < 34) return;

        // 2. Check EtherType at byte 12 and 13. IPv4 is 0x0800.
        if (raw[12] != 0x08 || raw[13] != 0x00) {
            return; // Not an IPv4 packet, ignore it safely
        }

        // Pass the pointer offset by 14 to skip the Ethernet header
        IPHeader ip(raw + 14);

        string src = ip.getSourceIP();

        packet_count[src]++;
        byte_count[src] += size;

        time_t now = time(0);

        // Dump stats every 1 second
        if (now - last_time >= 1) {
            for (auto& it : packet_count) {
                sendToPipe(it.first, it.second, byte_count[it.first]);
            }

            packet_count.clear();
            byte_count.clear();
            last_time = now;
        }
    }

    void start() {
        pcap_loop(handle, 0, callback, reinterpret_cast<u_char*>(this));
    }

    ~PacketSniffer() {
        if (handle) {
            pcap_close(handle);
            writeLog("INFO: Sniffer safely closed.");
        }
    }
};

// ---------------- MAIN ----------------
int main() {
    // Failsafe: if we can't write to the log, exit immediately
    if (!logFile.is_open()) {
        return 1; 
    }

    openPipe();

    // Check for root privileges silently
    if (geteuid() != 0) {
        writeLog("WARNING: Running without root privileges. Capture will likely fail.");
    }

    writeLog("INFO: Starting sniffer service...");

    pcap_if_t* alldevs;
    pcap_if_t* dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Get all available devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        writeLog("ERROR: Error finding devices: " + string(errbuf));
        return 1;
    }

    string selected_device = "";

    for (dev = alldevs; dev != NULL; dev = dev->next) {
        // Select first valid non-loopback active interface
        if (!(dev->flags & PCAP_IF_LOOPBACK) && dev->addresses != NULL) {
            selected_device = dev->name;
            break; // Essential: stops loop once a valid device is found
        }
    }

    // Free device list BEFORE using it
    pcap_freealldevs(alldevs);

    // Check if device found
    if (selected_device.empty()) {
        writeLog("ERROR: No valid network interface found.");
        return 1;
    }

    // Start sniffer
    PacketSniffer sniffer(selected_device);

    if (!sniffer.init()) {
        writeLog("ERROR: Failed to initialize sniffer on " + selected_device);
        return 1;
    }

    sniffer.start();

    return 0;
}
