
#include<iostream>
//#include<sys/socket.h>

#include <pcap/pcap.h>



static pcap_if_t * findDevice()
{
	char buf[PCAP_ERRBUF_SIZE];
	pcap_if_t* allDevs;
	if (pcap_findalldevs(&allDevs, buf) == -1) {
		std::cout << "Error in pcap_findalldevs: " << buf << std::endl;
		return nullptr;
	}

	for (pcap_if_t* device = allDevs; device; device = device->next) {
		if (device->flags & PCAP_IF_UP && device->flags & PCAP_IF_RUNNING &&
			(!strncmp(device->name, "eth", 3) || !strncmp(device->name, "en", 2) || !strncmp(device->name, "wl", 2))) {
			return device;
		}
	}
	return nullptr;
};


void process_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* buffer)
{
	std::cout << "Packet received" << std::endl;
}


int main()
{
	pcap_if_t* device = findDevice();
	if (!device) {
		std::cout << "No device found" << std::endl;
		return 1;
	}

	char buf[PCAP_ERRBUF_SIZE];
	pcap_t* handler = pcap_open_live(device->name, 65536, 1, 0, buf);
	if (!handler) {
		std::cout << "Handler error " << buf << std::endl;
		return 1;
	}

	u_char buffer[1024];
	int res = pcap_loop(handler, 0, process_packet, buffer);
	pcap_close(handler);
}

