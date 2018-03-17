extern "C" {
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
}

#include <iostream>
#include <vector>
#include <string>
#include <algorithm>

using namespace std;

vector<string> make_args(int argc, char* argv[]) {
    vector<string> args;
    for (int i {0}; i != argc; ++i) args.push_back(argv[i]);
    return args;
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
    
    {
        ifreq ifrcopy = ifr;
        if (ioctl(socket, SIOCGIFMTU, &ifrcopy) == -1) throw system_error{errno, generic_category()}; 
        cout << "MTU: " << ifrcopy.ifr_mtu << '\n';
    }


    close(socket);
}
