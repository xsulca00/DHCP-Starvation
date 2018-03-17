extern "C" {
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
}

#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <algorithm>

using namespace std;

vector<string> make_args(int argc, char* argv[]) {
    vector<string> args;
    for (int i {0}; i != argc; ++i) args.push_back(argv[i]);
    return args;
}

void print_mac(const uint8_t* octets) {
    cout.fill('0');
    cout << hex << setw(2) << unsigned{octets[0]} << ':'
              << setw(2) << unsigned{octets[1]} << ':'
              << setw(2) << unsigned{octets[2]} << ':'
              << setw(2) << unsigned{octets[3]} << ':'
              << setw(2) << unsigned{octets[4]} << ':'
              << setw(2) << unsigned{octets[5]} << '\n';
}


int main(int argc, char* argv[]) {
    vector<string> args {make_args(argc, argv)};
    if (args.size() != 3) throw runtime_error{"Usage: " + args[0] + " -i interface"};

    const string interface {args.back()};

    ifreq ifr {};
    ifr.ifr_addr.sa_family = AF_INET;
    copy_n(interface.cbegin(), IFNAMSIZ-1, &ifr.ifr_name[0]);
    ifr.ifr_name[IFNAMSIZ-1] = '\0';

    cout << "Interface: " << ifr.ifr_name << '\n';

    int socket {::socket(AF_INET, SOCK_DGRAM, 0)};

    // in_pktinfo info {};
    
    {
        
        ifreq ifrcopy {ifr};
        if (ioctl(socket, SIOCGIFHWADDR, &ifrcopy) == -1) throw system_error{errno, generic_category()}; 
        print_mac((uint8_t*)ifrcopy.ifr_hwaddr.sa_data);
    }


    close(socket);
}
