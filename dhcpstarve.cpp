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
#include <string>
#include <algorithm>

using namespace std;

using Mac_addr = array<uint8_t,6>;

vector<string> make_args(int argc, char* argv[]) {
    vector<string> args;
    for (int i {0}; i != argc; ++i) args.push_back(argv[i]);
    return args;
}

void print_mac(const Mac_addr& octets) {
    cout.fill('0');
    cout << hex   << setw(2) << unsigned{octets[0]} << ':'
                  << setw(2) << unsigned{octets[1]} << ':'
                  << setw(2) << unsigned{octets[2]} << ':'
                  << setw(2) << unsigned{octets[3]} << ':'
                  << setw(2) << unsigned{octets[4]} << ':'
                  << setw(2) << unsigned{octets[5]} << '\n';
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
    ifreq ifrcopy {ifr};
    if (ioctl(socket, SIOCGIFINDEX, &ifrcopy) == -1) throw system_error{errno, generic_category()};
    return ifrcopy.ifr_ifindex;
}

Mac_addr get_mac_address(int socket, const ifreq& ifr) {
    ifreq ifrcopy {ifr};
    if (ioctl(socket, SIOCGIFHWADDR, &ifrcopy) == -1) throw system_error{errno, generic_category()}; 

    const uint8_t* mac {reinterpret_cast<uint8_t*>(&ifrcopy.ifr_hwaddr.sa_data[0])};

    // ether_header eh {};
    // copy_n(mac, 6, &eh.ether_shost[0]);
    return {mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]};
}

struct Ethernet_frame {
    Mac_addr destination;
    Mac_addr source;
    uint16_t ethertype; 
    ip iphdr;
} __attribute__((packed));

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
    Mac_addr mac {get_mac_address(socket, ifr)};

    cout << "Interface ID: " << idx << '\n';

    print_mac(mac);

    /*
    in_pktinfo info {};
    info.ipi_ifindex = idx;
    */

    constexpr Mac_addr mac_broadcast {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    constexpr uint32_t ip_broadcast {0xffff};

    ip iphdr {};
    iphdr.ip_v = 4;
    iphdr.ip_hl = 5;
    iphdr.ip_tos = 0;
    iphdr.ip_len = htons(20);
    iphdr.ip_id = htons(200);
    iphdr.ip_off = 0;
    iphdr.ip_ttl = 255;
    iphdr.ip_p = 17;
    iphdr.ip_sum = 0;
    iphdr.ip_src.s_addr = 0;
    iphdr.ip_dst.s_addr = ip_broadcast;

    Mac_addr src {0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef};
    Mac_addr dst {mac_broadcast};
    // array<char,1500> data {"hello world"};

    Ethernet_frame frame {dst, src, htons(ETH_P_IP), iphdr};

    sockaddr_ll addr {};
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = idx;
    addr.sll_halen = ETHER_ADDR_LEN;
    addr.sll_protocol = htons(ETH_P_ARP);
    copy(mac_broadcast.cbegin(), mac_broadcast.cend(), &addr.sll_addr[0]);

    if (sendto(socket, &frame, sizeof(frame), 0, (sockaddr*)&addr, sizeof(addr)) == -1) throw system_error{errno, generic_category()};

    close(socket);
}
