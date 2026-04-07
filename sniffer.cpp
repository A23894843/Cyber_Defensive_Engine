#include <pcap.h>
#include <iostream>
#include <arpa/inet.h>
#include <map>
#include <ctime>
#include <fcntl.h>
#include <unistd.h>
#include <fstream>
using namespace std;

ofstream pipe("/tmp/packet_pipe");

void sendToPipe(string ip, int pkt, int bytes) {
    pipe << ip << "," << pkt << "," << bytes << endl;
    pipe.flush(); // VERY IMPORTANT
}

// ---------------- IP HEADER ----------------
class IPHeader {
    const u_char* data;

public:
    IPHeader(const u_char* packet) {
        data = packet + 14;
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
    int length;

public:
    Packet(const u_char* packet, int len) {
        rawData = packet;
        length = len;
    }

    int getSize() const {
        return length;
    }

    IPHeader getHeader() const {
        return IPHeader(rawData);
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
        handle = nullptr;
    }

    bool init() {
        char errbuf[PCAP_ERRBUF_SIZE];

        handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);

        if (!handle) {
            cerr << "Error: " << errbuf << endl;
            return false;
        }

        cout << "🚀 Sniffing on: " << device << endl;
        return true;
    }

    static void callback(u_char* user,
                         const pcap_pkthdr* header,
                         const u_char* packet) {

        PacketSniffer* sniffer = reinterpret_cast<PacketSniffer*>(user);
        sniffer->process(Packet(packet, header->len));
    }

    void process(const Packet& pkt) {
        IPHeader ip = pkt.getHeader();

        string src = ip.getSourceIP();
        int size = pkt.getSize();

        packet_count[src]++;
        byte_count[src] += size;

        time_t now = time(0);

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
        }
    }
};

// ---------------- MAIN ----------------
int main() {
    pcap_if_t* alldevs;
    pcap_if_t* dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Get all available devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "❌ Error finding devices: " << errbuf << endl;
        return 1;
    }

    string selected_device = "";

    // Debug: list all devices
    cout << "🔍 Available devices:\n";
    for (dev = alldevs; dev != nullptr; dev = dev->next) {
        cout << " - " << dev->name << endl;

        // Select first valid non-loopback active interface
        if (!(dev->flags & PCAP_IF_LOOPBACK) && dev->addresses != nullptr) {
            selected_device = dev->name;
        }
    }

    // Free device list BEFORE using it
    pcap_freealldevs(alldevs);

    // Check if device found
    if (selected_device.empty()) {
        cerr << "❌ No valid network interface found!" << endl;
        return 1;
    }

    cout << "✅ Using device: " << selected_device << endl;

    // Start sniffer
    PacketSniffer sniffer(selected_device);

    if (!sniffer.init()) {
        cerr << "❌ Failed to initialize sniffer" << endl;
        return 1;
    }

    sniffer.start();

    return 0;
}