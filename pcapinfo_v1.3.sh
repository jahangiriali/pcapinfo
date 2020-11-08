#!/usr/bin/bash

#
# Ali Jahangiri v1.3 Aug 2014 - v1.4 April 2019
#	This bash script utilizes capinfos and tshark to extract information from PCAP. This could be handy when you are analyzing large PCAP
# related to DDOS attacks.
#

# Check if capinfos & tshark exist.
type -P capinfos &>/dev/null || { echo "capinfos not found."; exit 1; }
type -P tshark &>/dev/null || { echo "tshark not found."; exit 1; }

# Receive pcap file name as argument.
pcapfile=$1

# Check if input pcap file supplied and readable.
if [ -f "$pcapfile" ]
	then

# Check file type.
filetype=`file $pcapfile | awk '{print $2;}'`

else
	echo "Usage: bash pcapinfo.sh YOURPCAP.pcap";
	exit
fi
# Check if the supplied file is PCAP.
if [ $filetype == "tcpdump" ]
	then

echo PCAP File Information
capinfos $pcapfile
echo ===================================================================
echo ---------Protocol Statistics-----------
tshark -r $pcapfile -q -z ptype,tree
echo ---------HTTP Statistics---------------
tshark -r $pcapfile -q -z http,stat,
echo -------HTTP Statistics with Rates------
tshark -r $pcapfile -q -z http,tree
echo ------------TOP 10 HTTP Request URL-----------------
echo ===================================================================
tshark -r $pcapfile -R http.request -T fields -e http.host | sed -e 's/?.*$//' | sed -e 's#^\(.*\)\t\(.*\)$#http://\1\2#' | sort | uniq -c | sort -rn | head -n 10
echo ===================================================================
echo ------------TOP 10 talkers by Source IP ------------------
echo ===================================================================
tshark -r $pcapfile -T fields -e ip.src | sort | uniq -c | sort -rn | head -10
echo ===================================================================
echo ------------TOP 10 talkers by DST IP ------------------
echo ===================================================================
tshark -r $pcapfile -T fields -e ip.dst | sort | uniq -c | sort -rn | head -10
echo ===================================================================
echo ------------TOP 10 talkers by port usage or SYN attempts---------------
echo ===================================================================
tshark -r $pcapfile -T fields -e ip.src "tcp.flags.syn==1 && tcp.flags.ack==0" | sort | uniq -c | sort -rn | head -10
echo ===================================================================
echo ------------HTTP 10 Response Code 200 and Content Type--------------
echo ===================================================================
tshark -r $pcapfile -R http.response.code==200 -T fields -e "http.content_type" |sort |uniq -c | sort -rn | head -10
echo ===================================================================
echo ------------TOP HTTP Host and Request Method--------------
echo ===================================================================
tshark -r $pcapfile -R http.host -T fields -e http.host -e http.request.method |sort |uniq -c | sort -rn | head -10
echo ===================================================================
echo ------TOP 10 DNS Query DST Host ------
echo ===================================================================
tshark -r $pcapfile -T fields -e dns.qry.name -R "dns.flags.response eq 0" |sort |uniq -c | sort -rn | head -10
echo ===================================================================
echo ------TOP 10 DNS Query by Soure IP ------
echo ===================================================================
tshark -r $pcapfile -T fields -e ip.src -R "dns.flags.response eq 0" |sort |uniq -c | sort -rn | head -10
echo ===================================================================
echo ---------- TOP 10 ICMP Conversations ----------
echo ===================================================================
tshark -r $pcapfile -V icmp -T fields -e icmp.ident -e ip.src |sort |uniq -c | sort -rn | head -10

else
	echo "Error: $pcapfile is not a PCAP file. Usage: bash pcapinfo.sh YOURPCAP.pcap";
fi
