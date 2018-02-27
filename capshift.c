#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "capshift.h"
#include "debug.h"

#define SWVERSION "v0.3 beta"
#define SWRELEASEDATE "February 2018"
#define DEBUG 0

// capshift (pCAP time SHIFT) shifts the timestamps in pcap files by the specified time
// delta value. 
// Written by Foeh Mannay & Niels Jakob Buch
// Please refer to http://networkbodges.blogspot.com for more information about this tool.
// This software is released under the Modified BSD license.

params_t *parseParams(int argc, char *argv[]){
	// Returns a struct with various parameters or NULL if invalid
	unsigned int i = 1;
	char 	*timestring = NULL,
			*endptr = NULL,
			*datestring = NULL,
			*offsetstring = NULL;
	params_t *parameters = (params_t*)malloc(sizeof(params_t));
	if(parameters == NULL) return(NULL);

	// Set some defaults
	parameters->infile = NULL;
	parameters->outfile = NULL;
	parameters->mode = 0;
	parameters->sign = ADD;

	// Look for the various flags, then store the corresponding value
	while(i < argc){
		if(strcmp(argv[i],"-r") == 0){
			parameters->infile = argv[++i];
			i++;
			continue;
		}
		if(strcmp(argv[i],"-w") == 0){
			parameters->outfile = argv[++i];
			i++;
			continue;
		}
		if(strcmp(argv[i],"-o") == 0){
			offsetstring = argv[++i];
			i++;
			continue;
		}
		if(strcmp(argv[i],"-d") == 0){
			datestring = argv[++i];
			i++;
			continue;
		}
		if(strcmp(argv[i],"-t") == 0){
			timestring = argv[++i];
			i++;
			continue;
		}
		// If we get any unrecognised parameters just fail
		return(NULL);
	}
	
	// If the input files still aren't set, bomb
	if((parameters->infile == NULL) || (parameters->outfile == NULL)) return(NULL);

	if ((datestring != NULL) && (timestring != NULL) && (offsetstring == NULL)) {
		// the case of exact time AND DATE, set parameters abs, secs, usecs and sign
		parameters->mode = 1; // Means absolute displacement

		char *result = malloc(strlen(datestring)+1+strlen(timestring)+1); //+1 for the null-terminator
    	//in real code you would check for errors in malloc here
    	strcpy(result, datestring);
    	strcat(result, " ");
		strcat(result, timestring);
		
		struct tm tm;
		time_t t;
		strptime(result, "%d-%m-%Y %H:%M:%S", &tm);
		tm.tm_isdst = -1;      /* Not set by strptime(); tells mktime()
								to determine whether daylight saving time
								is in effect */
		t = mktime(&tm);
		debug_print("Offset for mode 1: %d\n", (int)t);
		parameters->usecs = 0;
		parameters->secs = (int)t;

		return(parameters);
	}

	if ((datestring != NULL) && (timestring == NULL) && (offsetstring == NULL)) {
		// the case of exact date only (keep time-of-day), set parameters abs, secs, usecs and sign
		parameters->mode = 2; // Means absolute

		char *time = " 00:00:00";
		char *result = malloc(strlen(datestring)+strlen(time)+1); //+1 for the null-terminator
    	//in real code you would check for errors in malloc here
    	strcpy(result, datestring);
    	strcat(result, time);
		
		struct tm tm;
		time_t t;
		strptime(result, "%d-%m-%Y %H:%M:%S", &tm);
		tm.tm_isdst = -1;      /* Not set by strptime(); tells mktime()
								to determine whether daylight saving time
								is in effect */
		t = mktime(&tm);
		debug_print("DEBUG: Offset for mode 2: %d\n", (int)t);
		parameters->usecs = 0;
		parameters->secs = (int)t;

		return(parameters);
	}

	if ((datestring == NULL) && (timestring != NULL) && (offsetstring == NULL)) {
		// the case of exact time only, set parameters abs, secs, usecs and sign
		parameters->mode = 3; // Means absolute

		char *date = " 1-1-1970 ";
		char *result = malloc(strlen(date)+strlen(timestring)+1); //+1 for the null-terminator
    	//in real code you would check for errors in malloc here
    	strcpy(result, date);
    	strcat(result, timestring);
		
		struct tm tm;
		time_t t;
		strptime(result, "%d-%m-%Y %H:%M:%S", &tm);
		tm.tm_isdst = -1;      /* Not set by strptime(); tells mktime()
								to determine whether daylight saving time
								is in effect */
		t = mktime(&tm);
		debug_print("DEBUG: Offset for mode 3: %d\n", (int)t);
		parameters->usecs = 0;
		parameters->secs = (int)t;

		return(parameters);
	}

	if ((datestring == NULL) && (timestring == NULL) && (offsetstring != NULL)) {
		debug_print("DEBUG: A relative offset is the case...%s\n", offsetstring);
		// the case of exact offset, set parameters abs, secs, usecs and sign
		parameters->mode = 4; // Means relative
		// If there is a + or - present, set the sign accordingly
		switch(offsetstring[0]){
			case '-':
				parameters->sign = SUBTRACT;
				offsetstring++;
				break;
			case '+':
				parameters->sign = ADD;
				offsetstring++;
				break;
		}
		// If there are non-numeric characters present, bail out
		if((offsetstring[0] < '0') || (offsetstring[0] > '9')) return(NULL);

		// Grab the seconds
		parameters->secs = strtol(offsetstring, &endptr, 10);
		// Look for a decimal point, if present then grab and scale out microseconds
		if(endptr[0] == '.'){
			offsetstring = endptr + 1;
			parameters->usecs = strtol(offsetstring, &endptr, 10);

			// scale the usecs field as appropriate for place value
			i = endptr - offsetstring;
			while(i < 6){
				parameters->usecs *= 10;
				i++;
			}
			while(i > 6){
				parameters->usecs /= 10;
				i--;
			}
		} else parameters->usecs = 0;
		
		if(endptr[0] != '\x00') return(NULL);

		return(parameters);
	}

	
	
	

	return(parameters);
}

int parse_pcap(FILE *capfile, FILE *outfile, guint32 sign, guint32 secs, guint32 usecs, guint32 mode){
	char 				*memblock = NULL;
	guint32				caplen = 0;
	int					count = 0;
	pcaprec_hdr_t		*rechdr = NULL;
	int				first_timestamp_found = 0;
		
	// Start parsing the capture file:
	rewind(capfile);
	clearerr(capfile);
	memblock = (char*)malloc(sizeof(pcap_hdr_t));
	if(memblock == NULL){
		printf("Insufficient memory to load capture header.\n");
		return(0);
	}
	// Read the pcap header
	if(fread (memblock, 1, sizeof(pcap_hdr_t), capfile) != sizeof(pcap_hdr_t)){
		printf("Truncated capture file header - aborting.\n");
		if(memblock != NULL) free(memblock);
		return(0);
	}
	// Verify the magic number in the header indicates a pcap file
	if(((pcap_hdr_t*)memblock)->magic_number != 2712847316){
		printf("\nError!\nThis is not a valid pcap file. If it has been saved as pcap-ng\nconsider converting it to original pcap format with tshark or similar.\n");
		if(memblock != NULL) free(memblock); 
		return(0);
	}
	// Allocate memory for the PCAP record header
	rechdr = (pcaprec_hdr_t*)malloc(sizeof(pcaprec_hdr_t));
	if(rechdr == NULL){
		printf("Error: unable to allocate memory for pcap record header!\n");
		return(0);
	}
	// Clone the input file's header
	rewind(outfile);
	clearerr(outfile);
	if(fwrite(memblock, 1, sizeof(pcap_hdr_t), outfile) != sizeof(pcap_hdr_t)){
		printf("Error: unable to write pcap header to output file!\n");
		return(0);
	}

	// Read in each frame.
	while((!feof(capfile)) & (!ferror(capfile))) {
		free(memblock);
		// Get the packet record header and examine it for the packet size
		caplen = fread (rechdr, 1, sizeof(pcaprec_hdr_t), capfile);

		if(caplen != sizeof(pcaprec_hdr_t)){
			if(caplen > 0) printf("Error: Truncated pcap file reading record header, %u/%lu!\n", caplen, sizeof(pcaprec_hdr_t));
			break;
		}
				
		// Adjust timestamp as required, handling over/underflow
		if (first_timestamp_found == 0) {
			debug_print("Now seeing the first raw packet. Timestamp -> %d\n", (int)rechdr->ts_sec );
			first_timestamp_found = 1;

			switch(mode){
				case 1: // time and day fixed
					debug_print("Setting time and day (mode 1)\n", NULL);
					if ((int)rechdr->ts_sec > secs) {
						 secs = (int)rechdr->ts_sec - secs;
						 sign = SUBTRACT;
					} else {
						 secs = secs - (int)rechdr->ts_sec;
						 sign = ADD;
					}
					break;
				case 2: // date only
					debug_print("Setting date only (mode 2)\n", NULL);
					int timeofday = (int)rechdr->ts_sec % 86400;
					secs = secs + timeofday;
					if ((int)rechdr->ts_sec > secs) {
						 secs = (int)rechdr->ts_sec - secs;
						 sign = SUBTRACT;
					} else {
						 secs = secs - (int)rechdr->ts_sec;
						 sign = ADD;
					}
					break;
				case 3: // time only
					debug_print("Setting time only (mode 3)\n", NULL);
					timeofday = (int)rechdr->ts_sec % 86400;
					secs = (int)rechdr->ts_sec - timeofday + secs;
					if ((int)rechdr->ts_sec > secs) {
						 secs = (int)rechdr->ts_sec - secs;
						 sign = SUBTRACT;
					} else {
						 secs = secs - (int)rechdr->ts_sec;
						 sign = ADD;
					}
					break;
				case 4: // offset
					debug_print("Setting offset (mode 4)\n", NULL);
					break;
			}
			debug_print("Time adjustment sign:%d and value:%d", sign, secs);
		}

		if(sign == SUBTRACT){
			rechdr->ts_sec -= secs;
			if (usecs > rechdr->ts_usec){
				rechdr->ts_sec--;
				rechdr->ts_usec += (1000000 - usecs);
			} else {
				rechdr->ts_usec -= usecs;
			} 
		} else {
			rechdr->ts_sec += secs;
			rechdr->ts_usec += usecs;
			if (rechdr->ts_usec > 1000000){
				rechdr->ts_sec++;
				rechdr->ts_usec -= 1000000;
			}
		}

		caplen = rechdr->incl_len;
		
		memblock = malloc(caplen);
		if(memblock == NULL){
			printf("Error: Could not allocate memory for pcap data!\n");
			return(count);
		}
		// Get the actual packet data and copy it verbatim
		if(fread (memblock, 1, caplen, capfile) != caplen){
			printf("Error: Truncated pcap file reading capture!\n");
			break;
		}
		// Write the adjusted packet header
		if(fwrite(rechdr, 1, sizeof(pcaprec_hdr_t), outfile) != sizeof(pcaprec_hdr_t)){
			printf("Error: unable to write pcap record header to output file!\n");				
			return(0);
		}
		// Write the packet data
		if(fwrite(memblock, 1, caplen, outfile) != caplen){
			printf("Error: unable to write frame to output pcap file\n");
			return(0);
		}
		count++;
	}
	if(rechdr != NULL) free(rechdr);

	return(count);
}

int main(int argc, char *argv[]){
// The main function basically just calls other functions to do the work.
	params_t			*parameters = NULL;
	FILE				*infile = NULL,
						*outfile = NULL;
	
	// Parse our command line parameters and verify they are usable. If not, show help.
	parameters = parseParams(argc, argv);

	if(parameters == NULL){
		printf("\n\n                     _     _  __ _  \n"); 
 		printf("                    | |   (_)/ _| |     \n");
		printf("  ___ __ _ _ __  ___| |__  _| |_| |_    \n");
		printf(" / __/ _` | '_ \\/ __| '_ \\| |  _| __| \n");
		printf("| (_| (_| | |_) \\__ \\ | | | | | | |_  \n");
 		printf(" \\___\\__,_| .__/|___/_| |_|_|_|  \\__|\n");
 		printf("         | |                            \n");
 		printf("         |_|                            \n");
		printf("\ncapshift: a utility to adjust the timestamps of pcap files.\n");
		printf("Written by Niels Jakob Buch & Foeh Mannay.\n");
		printf("Version %s, %s\n\n", SWVERSION, SWRELEASEDATE);
		printf("Usage:\n");
		printf("%s -r inputcapfile -w outputcapfile [time option]\n\n",argv[0]);
		printf("Where inputcapfile is a tcpdump-style .cap file\n");
		printf("outputcapfile is the file where the time-shifted version will be saved\n");
		printf("[time option] is:\n");
		printf("	-o offset 		: offset is the number of seconds (and microseconds) to shift by (e.g. -1.5, +0.200)\n");
		printf("	-d date 		: where date is the day shift to, keeping the time-of-day.\n");	
		printf("	-t time 		: where time is the time-of-day to shift to, keeping the day.\n");
		printf("	-d date -t time		: where date and time is the time AND day to shift to.\n\n\n");
		return(1);
	}
	
	// Attempt to open the input capture file for reading:
	infile = fopen(parameters->infile,"rb");
	if (infile == NULL) {
		printf("\nError!\nUnable to open input capture file!\n");
		return(1);
	}
	// Attempt to open the output capture file for writing:
	outfile = fopen(parameters->outfile, "wb");
	if(outfile == NULL){
		printf("Error - could not open output file!\n");
		return(1);
	}
	
	printf("\n%d frames processed.\n", parse_pcap(infile, outfile, parameters->sign, parameters->secs, parameters->usecs, parameters->mode));

	fclose(infile);
	fclose(outfile);
	
	return(0);
}



