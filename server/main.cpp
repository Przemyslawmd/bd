
#include <iostream>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>


#include <pcap/pcap.h>

constexpr std::string_view FAKE_PROCESS_NAME = "/usr/sbin/apache2";


static pcap_if_t * findDevice()
{
	char buf[PCAP_ERRBUF_SIZE];
	pcap_if_t* allDevs;
	if (pcap_findalldevs(&allDevs, buf) == -1) {
		std::cout << "Error : pcap_findalldevs: " << buf << std::endl;
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


int main(int argc, char* argv[]) {

	setuid(0);
	setgid(0);

	prctl(PR_SET_NAME, FAKE_PROCESS_NAME, 0, 0, 0);
	strcpy(argv[0], FAKE_PROCESS_NAME.data());

	const pcap_if_t* device = findDevice();
	if (!device) {
		std::cout << "Error : findDevice" << std::endl;
		return 1;
	}
	std::cout << device->name << std::endl;

	char buf[PCAP_ERRBUF_SIZE];
	pcap_t* handler = pcap_open_live(device->name, 65536, 0, 1, buf);
	if (!handler) {
		std::cout << "Error : pcap_open_live" << std::endl;
		return 1;
	}

	constexpr char filter[] = "udp port 53";
	bpf_program fp = { 0 };
	if (pcap_compile(handler, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		std::cout << "Error : pcap_compile" << std::endl;
		pcap_close(handler);
		return 1;
	}

	if (pcap_setfilter(handler, &fp) == -1) {
		std::cout << "Error : pcap_setfilter" << std::endl;
		pcap_freecode(&fp);
		pcap_close(handler);
		return 1;
	}

	u_char buffer[1024];
	int res = pcap_loop(handler, 0, process_packet, buffer);
	pcap_close(handler);
}

