#include <pcap.h>
#include <string>
#include <arpa/inet.h>
#include <map>
#include <set>
#include <unordered_map>
#include <ctime>
#include <chrono>
#include <fcntl.h>
#include <unistd.h>
#include <fstream>
#include <cstdlib>
#include <iostream>
#include <sys/socket.h>
#include <sys/un.h>
#include <csignal>
#include <cstring>
#include <errno.h>
#include <oqs/oqs.h>
#include <sys/file.h>
#include <sys/stat.h>

using namespace std;

// --- Paths Configuration ---
const char* LOG_PATH = "/home/abhinandan-kali/Desktop/Cyber_Defensive_Engine/Cyber_Defensive_Engine.log";
const char* PIPE_PATH = "/home/abhinandan-kali/Desktop/Cyber_Defensive_Engine/packet_pipe";
const char* SOCK_PATH = "/home/abhinandan-kali/Desktop/Cyber_Defensive_Engine/Cyber_Defensive_Engine.sock";
const char* PQC_PUB_KEY_PATH = "/home/abhinandan-kali/Desktop/Cyber_Defensive_Engine/pqc_public_key.bin";

// --- Globals ---
ofstream logFile;
int pipe_fd = -1;
int client_fd = -1;
int server_fd = -1;

// PQC Globals
OQS_SIG *sig_ctx = nullptr;
uint8_t *public_key = nullptr;
uint8_t *secret_key = nullptr;

// Detection Thresholds
const int SCAN_THRESHOLD = 500;
const int TIME_WINDOW_MS = 1000;

struct ConnectionState {
    set<int> accessed_ports;
    std::chrono::high_resolution_clock::time_point first_packet_time;
};

// --- Utility Functions ---

void writeLog(const string& message) {
    if (logFile.is_open()) {
        time_t now = time(0);
        char* dt = ctime(&now);
        string timestamp(dt);
        timestamp.pop_back(); 
        logFile << "[" << timestamp << "] " << message << endl;
    }
}

bool send_all(int sock, const uint8_t* data, size_t length) {
    size_t total = 0;
    while (total < length) {
        ssize_t sent = send(sock,
                            data + total,
                            length - total,
                            MSG_NOSIGNAL);
        if (sent <= 0)
            return false;
        total += sent;
    }   return true;
}

void init_pqc() {
    OQS_init(); 
    // Attempt to use the standardized ML-DSA (formerly Dilithium) name
    sig_ctx = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44); 
    
    if (!sig_ctx) {
        // Fallback: Try the legacy name if your liboqs is slightly older
        sig_ctx = OQS_SIG_new("Dilithium2");
    }

    if (!sig_ctx) {
        cerr << "CRITICAL: PQC algorithm initialization failed! Check liboqs version." << endl;
        exit(1);
    }
    public_key = (uint8_t *)malloc(sig_ctx->length_public_key);
    secret_key = (uint8_t *)malloc(sig_ctx->length_secret_key);
    
    if (OQS_SIG_keypair(sig_ctx, public_key, secret_key) != OQS_SUCCESS) {
        cerr << "CRITICAL: PQC Keypair generation failed!" << endl;
        exit(1);
    }
    
    // 1. Save public key for the Python ML module
    FILE *f = fopen(PQC_PUB_KEY_PATH, "wb");
    if (f) {
        fwrite(public_key, 1, sig_ctx->length_public_key, f);
        fclose(f);
        writeLog("INFO: PQC Keys generated and public key saved.");
    }

    // 2. Save private key for the Python Flask app (THIS WAS MISSING)
    FILE *f_priv = fopen("/home/abhinandan-kali/Desktop/Cyber_Defensive_Engine/sniffer_private_key.bin", "wb");
    if (f_priv) {
        fwrite(secret_key, 1, sig_ctx->length_secret_key, f_priv);
        fclose(f_priv);
    }
}

void setup_ipc() {
    // 1. Setup Unix Domain Socket (UDS) Server
    // Ignore SIGPIPE to prevent the sniffer from crashing if the Python engine disconnects
    signal(SIGPIPE, SIG_IGN); 

    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        cerr << "CRITICAL: Failed to create UDS socket: " << strerror(errno) << endl;
        exit(1);
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);

    // Remove old socket file if it exists to allow a fresh bind
    unlink(SOCK_PATH);
    
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        cerr << "CRITICAL: UDS Bind failed: " << strerror(errno) << endl;
        exit(1);
    }

    // Start listening for the Python connection
    if (listen(server_fd, 5) < 0) {
        cerr << "CRITICAL: UDS Listen failed: " << strerror(errno) << endl;
        exit(1);
    }

    // Set permissions so the Python process (even if not root) can access the socket
    chmod(SOCK_PATH, 0666);
    
    // Set to non-blocking so the sniffer doesn't hang while waiting for Python
    fcntl(server_fd, F_SETFL, O_NONBLOCK);

    // 2. Setup Named Pipe (FIFO) for deterministic alerts (SCAN/STATS)
    // Ensure the pipe file exists on the disk [cite: 1]
    mkfifo(PIPE_PATH, 0666); 
    chmod(PIPE_PATH, 0666);
    
    // Open the pipe in non-blocking mode
    // This allows the sniffer to keep running even if the Python UI isn't reading yet
    pipe_fd = open(PIPE_PATH, O_WRONLY | O_NONBLOCK);
    
    if (pipe_fd == -1 && errno != ENXIO) {
        cerr << "Warning: Named pipe initialization failed." << endl;
    }

    writeLog("INFO: IPC Channels initialized and permissions set.");
    cout << "IPC Handshake: UDS Server live at " << SOCK_PATH << endl;
}

void relay_to_python_pqc(const uint8_t* packet_data, uint32_t length) {
    if (client_fd == -1) {
        int new_client = accept(server_fd, NULL, NULL);
        if (new_client >= 0) {
            client_fd = new_client;
            
            // REMOVE OR COMMENT OUT THIS LINE:
            // fcntl(client_fd, F_SETFL, O_NONBLOCK); 
            
            writeLog("INFO: ML Module handshake complete via UDS.");
        } else return;
    }

    // PQC Signing
    size_t sig_len;
    uint8_t *signature = (uint8_t *)malloc(sig_ctx->length_signature);
    if (OQS_SIG_sign(sig_ctx, signature, &sig_len, packet_data, length, secret_key) != OQS_SUCCESS) {
        free(signature);
        return;
    }

    // Structured Header [Total Size][Sig Size][Packet Size]
    uint32_t total_payload = (uint32_t)sig_len + length;
    uint32_t headers[3] = { htonl(total_payload), htonl((uint32_t)sig_len), htonl(length) };

    // Send Data
    if (!send_all(client_fd, (uint8_t*)headers, 12) ||
    !send_all(client_fd, signature, sig_len) ||
    !send_all(client_fd, packet_data, length)) {

        close(client_fd);
        client_fd = -1;
    }

    free(signature);
}

void sendToPipe(string type, string ip, string info) {
    if (pipe_fd != -1) {
        string data = type + "," + ip + "," + info + "\n";
        if (write(pipe_fd, data.c_str(), data.size()) < 0) {
            // Pipe might be closed by UI
        }
    }
}

// --- Sniffer Core ---

class PacketSniffer {
    map<string, int> packet_count;
    map<string, int> byte_count;
    unordered_map<string, ConnectionState> port_scan_monitor; 
    time_t last_time;
    pcap_t* handle;
    string device;

public:
    PacketSniffer(const string& dev) : device(dev), last_time(time(0)), handle(NULL) {}

    bool init() {
        char errbuf[PCAP_ERRBUF_SIZE];
        handle = pcap_open_live(device.c_str(), 65535, 1, 10, errbuf);
        return (handle != NULL);
    }

    static void callback(u_char* user, const pcap_pkthdr* header, const u_char* packet) {
        PacketSniffer* snf = reinterpret_cast<PacketSniffer*>(user);
        
        // PQC Relay
        relay_to_python_pqc(packet, header->caplen);

        // Traffic Analysis
        if (header->caplen >= 34 && packet[12] == 0x08 && packet[13] == 0x00) {
            char src_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, packet + 26, src_ip, INET_ADDRSTRLEN);
            string src(src_ip);
            
            snf->packet_count[src]++;
            snf->byte_count[src] += header->caplen;

            // Port Scan Logic
            int protocol = packet[23];
            if (protocol == 6 || protocol == 17) {
                int ip_hl = (packet[14] & 0x0F) * 4;
                int d_port = (packet[14 + ip_hl + 2] << 8) | packet[14 + ip_hl + 3];
                
                auto now = std::chrono::high_resolution_clock::now();
                auto& state = snf->port_scan_monitor[src];
                
                if (state.accessed_ports.empty()) state.first_packet_time = now;
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - state.first_packet_time).count();
                
                if (elapsed > TIME_WINDOW_MS) {
                    state.accessed_ports.clear();
                    state.first_packet_time = now;
                }
                
                state.accessed_ports.insert(d_port);
                if (state.accessed_ports.size() >= SCAN_THRESHOLD) {
                    sendToPipe("SCAN", src, to_string(state.accessed_ports.size()));
                    writeLog("CRITICAL: PQC-Authenticated Port Scan Alert: " + src);
                    string cmd = "sudo iptables -A INPUT -s " + src + " -j DROP";
                    system(cmd.c_str());
                    state.accessed_ports.clear();
                }
            }
        }

        // Periodic Stats
        time_t now_sec = time(0);
        if (now_sec - snf->last_time >= 1) {
            for (auto const& [ip, cnt] : snf->packet_count) {
                sendToPipe("STATS", ip, to_string(cnt));
            }
            snf->packet_count.clear();
            snf->last_time = now_sec;
        }
    }

    void start() { pcap_loop(handle, 0, callback, reinterpret_cast<u_char*>(this)); }
};

void handle_exit(int signum) {
    // Clean up the lock file and socket file so the next run starts fresh
    unlink("/home/abhinandan-kali/Desktop/Cyber_Defensive_Engine/sniffer.pid");
    unlink("/home/abhinandan-kali/Desktop/Cyber_Defensive_Engine/Cyber_Defensive_Engine.sock");
    
    // Clean up the private key
    unlink("/home/abhinandan-kali/Desktop/Cyber_Defensive_Engine/sniffer_private_key.bin");
    
    // Explicitly write to log if possible before exiting
    exit(signum);
}

int main() {
    // Register signal handlers for clean termination
    signal(SIGINT, handle_exit);  // Triggered by Ctrl+C
    signal(SIGTERM, handle_exit); // Triggered by 'sudo kill'

    int lock_fd = open("/home/abhinandan-kali/Desktop/Cyber_Defensive_Engine/sniffer.pid", O_RDWR | O_CREAT, 0666);
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX | LOCK_NB) < 0)   {
        cerr << "CRITICAL: Another sniffer instance is already running!" << endl;
        return 1;
    }
    logFile.open(LOG_PATH, ios::app);
    init_pqc();
    setup_ipc();

    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) return 1;

    string dev_name = alldevs->name; // Defaulting to first interface
    pcap_freealldevs(alldevs);

    PacketSniffer sniffer(dev_name);
    if (!sniffer.init()) return 1;

    cout << "Defensive Engine [PQC ENABLED] running on " << dev_name << "..." << endl;
    sniffer.start();

    // Final Cleanup
    handle_exit(0);
    return 0;
}