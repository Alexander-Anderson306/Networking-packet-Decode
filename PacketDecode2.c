//Written By Alexander Anderson 5/9/26
#ifdef _WIN32
	#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>

#define INPUT_PATTERN "Expected input: %s, <input_bin_file>\n"
#define PROGRAM_NAME "Packet_Decode"
void print_ethernet_header(FILE* file);
void print_ip_header(FILE* file);
void print_payload(FILE* file);

int main(int argc, char** argv) {
	int ret_val = 0;
	FILE* file;
	if(argc != 2) {
		fprintf(stderr, "ERROR: Invalid number of inputs.\n");
		fprintf(stderr, INPUT_PATTERN, PROGRAM_NAME);
		ret_val = 1;
	} else {
		//check if the file could be read
		file = fopen(argv[1], "rb");

		if(file == NULL) {
			fprintf(stderr, "ERROR: File could not be open\n");
			fprintf(stderr, INPUT_PATTERN, PROGRAM_NAME);
			ret_val = 2;
		} else {
			//decode the packet
			print_ethernet_header(file);
			print_ip_header(file);
			print_payload(file);
			fclose(file);
		}
	}

	return ret_val;
}


/**
	* This function prints the eithernet header of a packet.
	* Assumes the file is properly formatted.
**/ 
void print_ethernet_header(FILE* file) {
	unsigned char uch = 0;
	//print the ethernet header title then the first part of the destination MAC address
	printf("Ethernet header:\n----------------\nDestination MAC address:\t");
	for(int i = 0; i < 5; i++) {
		uch = fgetc(file);
		printf("%02x:", uch);
	}
	uch = fgetc(file);
	printf("%02x\n", uch);

	//print thesource MAC address
	printf("Source MAC address:\t\t");
	for(int i = 0; i < 5; i++) {
		uch = fgetc(file);
		printf("%02x:", uch);
	}
	uch = fgetc(file);
	printf("%02x\n", uch);
	
	//print the type
	uch = fgetc(file);
	printf("Type:\t\t\t\t%02x", uch);
	uch = fgetc(file);
	printf("%02x\n", uch);

}

/**
 	* This function reads the IP header of a recieved packet.
	* This function expects that there are no erros with the provided binary file
**/
void print_ip_header(FILE* file) {
	unsigned char uch = 0;
	unsigned int temp = 0;
	unsigned char options_flag = 0;
	printf("\nIPv4 Header:\n----------------\nVersion:\t\t\t");
	uch = fgetc(file);
	//getting the version
	temp = uch >> 4;
	printf("%02x\n", temp);
	
	printf("Internet header length:\t\t");
	//getting IHL
	temp = uch & 0b00001111;
	printf("%02x\n", temp);
	//set options flag
	options_flag = temp - 5;

	printf("DSCP:\t\t\t\t");
	uch = fgetc(file);
	//getting DSCP
	temp = uch >> 2;
	printf("%02x\n", temp);

	printf("ECN:\t\t\t\t");
	//getting ECN
	temp = uch & 0b00000011;
	printf("%02x\t", temp);
	//epic ecn switch
	switch (temp) {
		case 0b00:
			printf("Non-ECN Packet\n");
			break;
		case 0b11:
			printf("ECN-Capable Packet Conjestion experienced\n");
			break;
		default:
			printf("ECN-Packet\n");
	}

	printf("Total Length:\t\t\t");
	//getting total length (2 bytes)
	temp = fgetc(file);
	uch = fgetc(file);
	temp = (temp << 8) | uch;
	printf("%u\n", temp);

	printf("Identification:\t\t\t");
	//getting identification (2 bytes)
	temp = fgetc(file);
	uch = fgetc(file);
	temp = (temp << 8) | uch;
	printf("%u\n", temp);

	printf("Flags\t\t\t\t");
	//getting DF flag
	uch = fgetc(file);
	temp = uch & 0b01000000;

	if(temp) {
		printf("Don't Fragment\n");
	} else {
		//getting MF flag
		temp = uch & 0b00100000;
		if(temp) {
			printf("Fragment\n");
		} else {
			printf("Last Fragment\n");
		}
	}
	
	printf("Fragment Offset:\t\t");
	//getting fragment offset
	temp = uch & 0b00011111;
	uch = fgetc(file);
	temp = (temp << 8) | uch;
	printf("%u\n", temp);

	printf("Time to Live:\t\t\t");
	//getting ttl
	uch = fgetc(file);
	printf("%u\n", uch);

	printf("Protocol\t\t\t");
	//getting protocol
	uch = fgetc(file);
	printf("%u\n", uch);

	printf("IP Checksum:\t\t\t");
	//getting checksum (two bytes)
	temp = fgetc(file);
	uch = fgetc(file);
	temp = (temp << 8) | uch;
	printf("0x%x\n", temp);

	printf("Source IP Address:\t\t");
	for(int i = 0; i < 3; i++) {
		//reading current part of ip address
		uch = fgetc(file);
		printf("%u.", uch);
	}
	uch = fgetc(file);
	printf("%u\n", uch);

	printf("Destination IP Address:\t\t");
	for(int i = 0; i < 3; i++) {
		//reading current part of ip address
		uch = fgetc(file);
		printf("%u.", uch);
	}
	uch = fgetc(file);
	printf("%u\n", uch);

	//if we have options loop any print however many words we have
	if(options_flag) {
		for(int i = 0; i < options_flag; i++) {
			uch = fgetc(file);
			printf("IP Option Word #%d:\t\t0x%02x", i, uch);
			uch = fgetc(file);
			printf("%02x", uch);
			uch = fgetc(file);
			printf("%02x", uch);
			uch = fgetc(file);
			printf("%02x\n", uch);
		}
	} else {
		printf("Options\t\t\t\tNo Options\n");
	}
}
/**
	* This function prints the rest of the pay load from a packet
	* This function expects that there are no errors with the rest of the given binary file
**/
void print_payload(FILE* file) {
	unsigned char uch = 0;
	unsigned int byte_count = 1;
	//print the payload
	printf("\nPayload:\n");
	
	uch = fgetc(file);
	//check the next byte is not feof
	while((!feof(file))) {
		if(byte_count % 32 == 0) {
			printf("%02x\n", uch);
		} else if(byte_count % 8 == 0) {
			printf("%02x   ", uch);
		} else {
			printf("%02x ", uch);
		}
		++byte_count;

		uch = fgetc(file);
	}
}

