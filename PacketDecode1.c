//Written By Alexander Anderson 4/18/26
#ifdef _WIN32
	#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>

#define INPUT_PATTERN "Expected input: %s, <input_bin_file>\n"
#define PROGRAM_NAME "Packet_Decode"
void print_ethernet_header(FILE* file);

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
			//handle the eithernet header
			print_ethernet_header(file);
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
	unsigned int byte_count = 1;
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

