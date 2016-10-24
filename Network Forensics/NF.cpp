#include <stdio.h>
#include <iostream>
#include <sstream>
#include <stdlib.h>
#include <fstream>
#include <string>
#include <cstring>
#include <vector>
#include <set>
#include <map>
#include <iterator>
#include <algorithm>
#include <math.h>
#include <ctype.h>
using namespace std;

typedef unsigned short WORD;
typedef unsigned char BYTE;

unsigned int BUFFER_SIZE = 30000000;
WORD GLOBAL_HEADER = 24;//why header size is 40 ?
WORD RECORD_HEADER = 16;
WORD ETHERNET_HEADER = 14;
WORD IP_HEADER = 20;
WORD PACKET_LENGTH_ADDRESS = 2;
string IP_PROTOCOL="0800";
string SERVER_PORT_HTTP = "80";
string SERVER_PORT_HTTPS = "443";
string TCP ="06"; // Record Header + 17 postion
string UDP="11"; // Record Header + 17 postion
string HTTP_REQ_SIG = " HTTP/1.1\r\n";

struct Packet {
	int no;
	unsigned long int seqNo;
	unsigned long int ackNo;
	string timestamp;
	string sourceIp;
	string sourcePort;
	string destIp;
	string destPort;
	string protocol;
	string protocolType;
	string payload;
	int totalLen;
	int payLoadLen;
	int tcpHeaderLen;
	int ipHeaderLen;
};
struct SecTaskOp {
	map<string,vector<Packet> > connection;
	map<string,vector<Packet> > data;
	vector<string> key;
};

/*Reads the input file*/
vector<char> readFile() {
	char *buf = (char*) malloc(sizeof(char) * BUFFER_SIZE);
	FILE *file = stdin;
//	FILE *file = fopen("E:\\Box Sync\\Projects\\Network Forsenics\\NF\\src\\task3.test1.pcap", "rb");
	size_t record;
	vector<char> rawData;
	if (file) {
		while ((record = fread(buf, 1, BUFFER_SIZE, file)) > 0) {
			if(std::ferror(file) && !std::feof(file))
				cout<<"Error";
			rawData.insert(rawData.end(), buf, buf+record);
		}
		if (ferror(file)) {
			cout<<"Error";
		}
		fclose(file);
	}
	return rawData;
}

/*
 * data is ascii string. Each element of data is a byte
 * Test Data - //0000 - 0//FFFF - 65535//aa00 - 43520//00aa - 170//1010 - 4112//a0a0 - 41120//5060 - 20576//0504 - 1284//c00b - 49163//c0d - 3085
 *
 */
string cnvAsciiHex(string data) {
	int i;
	string hexData;
	for(i=0;i<data.length();i++) {
		int byteFormat = ((int)((unsigned char)data[i])); // Converts each ascii element to decimal equivalent
		char nibbleBuf[2];
		if(byteFormat/16 > 0) {
			sprintf(nibbleBuf,"%x",byteFormat);
		} else {
			sprintf(nibbleBuf,"0%x",byteFormat); // zero has to be appended before hex data
		}
		hexData.append(nibbleBuf);
	}
	return hexData;
}

int cnvHexInt (string hexData) {
	char *hexbuff = &hexData[0];
	int deciData = strtol(hexbuff, NULL, 16); // Converts the hex string to decimal Equivalent
	return deciData;
}

unsigned long int cnvHexLongInt (string hexData) {
	char *hexbuff = &hexData[0];
	unsigned long int deciData = strtol(hexbuff, NULL, 16); // Converts the hex string to decimal Equivalent
	return deciData;
}

string intToStr(unsigned long int num) {
	ostringstream buffer;
	buffer << num;
	return buffer.str();
}
string intToHx(int value) {
	stringstream ss;
	ss<< std::hex << value; // int decimal_value
	string result ( ss.str() );
	return result;
}

string intToStr(int num) {
	ostringstream buffer;
	buffer << num;
	return buffer.str();
}
int strToInt(string num){
	char *buffer = &num[0];
	int value = strtol(buffer, NULL, 10);
	return value;
}

string cnvAsciiIpAd(string ipAdAs) {
	int i;
	string ipAd;
	for(i=0;i<ipAdAs.length();i++) {
		string buffer(1,ipAdAs[i]);
		ipAd.append(intToStr(cnvHexInt((cnvAsciiHex(buffer)))));
		if(i != ipAdAs.length()-1) {
			ipAd.append(".");
		}
	}
	return ipAd;
}
string getPacketData(Packet packet) {
	string pkt ="sequenceNo:: "+intToStr(packet.seqNo)+"\nsource:: "+packet.sourceIp+":"+packet.sourcePort+" dest:: "+packet.destIp+":"+packet.destPort+"\nprotocol:: "+packet.protocol+" -protocolType ::"+packet.protocolType;
	return pkt;
}

/*
 * Payload Size = Total Length - IP Header - Transport Header
 */
int calculatePayloadLen(Packet packet) {
	int payloadLen = (packet.totalLen) - (packet.ipHeaderLen) - (packet.tcpHeaderLen);
	return payloadLen;
}

/*
 * From http://www.sbin.org/
 */
void Tokenize(const string& str,vector<string>& tokens,const string& delimiters = " ")
{
    // Skip delimiters at beginning.
    string::size_type lastPos = str.find_first_not_of(delimiters, 0);
    // Find first "non-delimiter".
    string::size_type pos     = str.find_first_of(delimiters, lastPos);
    while (string::npos != pos || string::npos != lastPos)
    {
        // Found a token, add it to the vector.
        tokens.push_back(str.substr(lastPos, pos - lastPos));
        // Skip delimiters.  Note the "not_of"
        lastPos = str.find_first_not_of(delimiters, pos);
        // Find next "non-delimiter"
        pos = str.find_first_of(delimiters, lastPos);
    }
}

string cnvRevAsciiHx(string data) {
	int i;
	string hexData;
	for(i=data.length();i>=0;i--) {
		int byteFormat = ((int)((unsigned char)data[i])); // Converts each ascii element to decimal equivalent
		char nibbleBuf[2];
		if(byteFormat/16 > 0) {
			sprintf(nibbleBuf,"%x",byteFormat);
		} else {
			sprintf(nibbleBuf,"0%x",byteFormat); // zero has to be appended before hex data
		}
		hexData.append(nibbleBuf);
	}
	return hexData;
}
int cnvAsciiInt(string data,int lr) {
	int i;
	string hexData;
	if(lr == 0) {
		for(i=data.length();i>=0;i--) {
			int byteFormat = ((int)((unsigned char)data[i])); // Converts each ascii element to decimal equivalent
			char nibbleBuf[2];
			if(byteFormat/16 > 0) {
				sprintf(nibbleBuf,"%x",byteFormat);
			} else {
				sprintf(nibbleBuf,"0%x",byteFormat); // zero has to be appended before hex data
			}
			hexData.append(nibbleBuf);
		}
	} else {
		for(i=0;i<data.length();i++) {
			int byteFormat = ((int)((unsigned char)data[i])); // Converts each ascii element to decimal equivalent
			char nibbleBuf[2];
			if(i!=0) {
				if(byteFormat/16 > 0) {
					sprintf(nibbleBuf,"%x",byteFormat);
				} else {
					sprintf(nibbleBuf,"0%x",byteFormat); // zero has to be appended before hex data
				}
			} else {
				sprintf(nibbleBuf,"%x",byteFormat); // Each decimal equivalent is converted to hex equivalent (170 > aa)
			}
			hexData.append(nibbleBuf);
		}
	}
	char *hexbuff = &hexData[0];
	int deciData = strtol(hexbuff, NULL, 16); // Converts the hex string to decimal Equivalent
	return deciData;
}

/*
 * ParsePacket function reads the packet and parses the packet information
 * RECORD_HEADER + Ethernet_header
 */
Packet parsePacket(string pkt) {
	Packet packet;
	WORD sTimestampPos = 0;
	WORD nTimestampPos = 4;
	WORD protocolPos = RECORD_HEADER + 12;// l = 2
	WORD ipHeadLenPos = RECORD_HEADER + 14; // l = 1
	WORD packetLenPos = RECORD_HEADER + 16;// l = 4
	WORD protocolTypePos = RECORD_HEADER + 23;// l = 1
	WORD sourceIpPos = RECORD_HEADER + 26; // l = 4
	WORD destIpPos = RECORD_HEADER + 30; // l = 4

	string protocolAs(&pkt[protocolPos], 2);
	string protocolTypeAs(&pkt[protocolTypePos], 1);
	string protocolHx = cnvAsciiHex(protocolAs);
	packet.protocol = protocolHx;
	string protocolTypeHx = cnvAsciiHex(protocolTypeAs);
	packet.protocolType = protocolTypeHx;
	if (protocolTypeHx == TCP) {
		string ipHeadLenAs(&pkt[ipHeadLenPos],1);
		string ipHeadLenHx = cnvAsciiHex(ipHeadLenAs);
		packet.ipHeaderLen = cnvHexInt(string(1,ipHeadLenHx[1])) * 4;
		WORD sourcePortPos = RECORD_HEADER +ETHERNET_HEADER+ packet.ipHeaderLen; // l = 2
		WORD destPortPos = RECORD_HEADER + ETHERNET_HEADER+ packet.ipHeaderLen + 2; // l = 2
		WORD seqNoPos = RECORD_HEADER + ETHERNET_HEADER + packet.ipHeaderLen + 4;// l = 4
		WORD ackNoPos = RECORD_HEADER + ETHERNET_HEADER + packet.ipHeaderLen + 8;// l = 4
		WORD tcpHeadLenPos = RECORD_HEADER + ETHERNET_HEADER + packet.ipHeaderLen+ 12; // l = 1
		string sourceIpAs(&pkt[sourceIpPos], 4);
		string sourcePortAs(&pkt[sourcePortPos],2);
		string destPortAs(&pkt[destPortPos],2);
		string destIpAs(&pkt[destIpPos], 4);
		string sourcePortHx = cnvAsciiHex(sourcePortAs);
		packet.sourceIp = cnvAsciiIpAd(sourceIpAs);
		packet.sourcePort = intToStr(cnvHexInt(sourcePortHx));
		string destPortHx = cnvAsciiHex(destPortAs);
		packet.destIp = cnvAsciiIpAd(destIpAs);
		packet.destPort = intToStr(cnvHexInt(destPortHx));
		string packetLenAs(&pkt[packetLenPos],2);
		string packetLenHx = cnvAsciiHex(packetLenAs);
		packet.totalLen = cnvHexInt(packetLenHx);
		string tcpHeadLenAs(&pkt[tcpHeadLenPos],1);
		packet.tcpHeaderLen = cnvHexInt(string(1,cnvAsciiHex(tcpHeadLenAs)[0])) * 4;
		string seqNoAs(&pkt[seqNoPos],4);
		packet.seqNo = cnvHexLongInt(cnvAsciiHex(seqNoAs));
		string ackNoAs(&pkt[ackNoPos],4);
		packet.ackNo = cnvHexLongInt(cnvAsciiHex(ackNoAs));
		packet.payLoadLen = calculatePayloadLen(packet);
		int payloadPos = RECORD_HEADER + ETHERNET_HEADER + packet.tcpHeaderLen + packet.ipHeaderLen;
		string payloadAs (&pkt[payloadPos],packet.payLoadLen);
		packet.payload = payloadAs;
		string ntimestampAs(&pkt[nTimestampPos],4);
		string stimestampAs(&pkt[sTimestampPos],4);
		packet.timestamp= cnvRevAsciiHx(stimestampAs)+cnvRevAsciiHx(ntimestampAs);
	}
	return packet;
}

/*
 * Consolidate related packets together in a map
 */
void consolidateTCPPkt(set<string> &packetSet,map<string,vector<Packet> > &consPackets,Packet packet,set<unsigned long int> &duplicateReqCk,set<unsigned long int> &duplicateResCk) {
	string ad;
	string temp;
	/* Following condition has been added for Task 2 as only port 80 is considered*/
	if(packet.sourcePort == SERVER_PORT_HTTP || packet.destPort == SERVER_PORT_HTTP) {
		if(packet.sourcePort == SERVER_PORT_HTTP) {
			temp = packet.destIp +" "+ packet	.destPort + " " + packet.sourceIp +" "+ packet.sourcePort;
			ad = packet.destIp +" "+ packet	.destPort + " " + packet.sourceIp +" "+ packet.sourcePort+" res";
			if(duplicateResCk.find(packet.seqNo) == duplicateResCk.end()) {
				if(consPackets.count(ad) == 0) { //Create New list as the combination is not found
					packetSet.insert(temp);
					vector<Packet> packets;
					packets.push_back(packet);
					consPackets.insert(pair<string, vector<Packet> >(ad, packets));
				} else {
					(consPackets.find(ad)->second).push_back(packet);
				}
				if(packet.payLoadLen > 0)
					duplicateResCk.insert(packet.seqNo);
			} else {
//				 if(packet.payLoadLen > 0) {
//
//				 } else
//					 cout<<"Duplicate !!"<<endl;
			}
		} else {
			temp = ad = packet.sourceIp +" "+ packet.sourcePort + " " + packet.destIp +" "+ packet.destPort;
			ad = packet.sourceIp +" "+ packet.sourcePort + " " + packet.destIp +" "+ packet.destPort+" req";
			if(duplicateReqCk.find(packet.seqNo) == duplicateReqCk.end()) {
				if(consPackets.count(ad) == 0) { //Create New list as the combination is not found
					packetSet.insert(temp);
					vector<Packet> packets;
					packets.push_back(packet);
					consPackets.insert(pair<string, vector<Packet> >(ad, packets));
				} else {
					(consPackets.find(ad)->second).push_back(packet);
				}
				if(packet.payLoadLen > 0)
					duplicateReqCk.insert(packet.seqNo);
			} else {
//				 if(packet.payLoadLen > 0) {
//
//				 } else
//					 cout<<"Duplicate !!"<<endl;
			}
		}
	}
}
bool compareBySeqNo(const Packet &a,const Packet &b) {
	return a.seqNo < b.seqNo;
}
bool compareByIP(const string &a,const string &b) {
	return a.compare(b) < 0;
}
bool compareByTimestamp(const string &a,const string &b) {
	return a.compare(b) < 0;
}

void getTcpData(set<string> &packetSet,map<string,vector<Packet> > &consPackets) {
	vector<string> connection;
	vector<string> data;

	vector<string> packetLst(packetSet.begin(),packetSet.end());
	sort(packetLst.begin(), packetLst.end(), compareByIP);
	int i;
	for(i=0;i<packetLst.size();i++) {
		vector<Packet> packetsRes = consPackets[packetLst[i]+ " res"];
		sort(packetsRes.begin(), packetsRes.end(), compareBySeqNo);
		vector<Packet> packetsReq = consPackets[packetLst[i]+ " req"];
		sort(packetsReq.begin(), packetsReq.end(), compareBySeqNo);
		int j;
		int upStreamSize = 0;
		int downStreamSize = 0;
		for(j=0;j<packetsReq.size();j++) {
			upStreamSize+=packetsReq[j].payLoadLen;
			data.push_back(packetsReq[j].payload);
		}
		for(j=0;j<packetsRes.size();j++) {
			downStreamSize+=packetsRes[j].payLoadLen;
			data.push_back(packetsRes[j].payload);
		}
		string connectionData = packetLst[i]+" "+intToStr(upStreamSize)+" "+intToStr(downStreamSize);
		connection.push_back(connectionData);
	}
	for(i=0;i<connection.size();i++) {
		cout<<connection[i]<<endl;
	}
	for(i=0;i<data.size();i++) {
		cout<<data[i];
	}
}

/*
 * Gives First string between two string
 */
string findSubStr(string text,string start,string end ){
	int temp = text.find(start);
	int startPos = temp +start.length();
	if(startPos == -1 || temp > text.length()) {
		return "";
	} else {
		string subStr(&text[startPos],&text[text.length()]);
		int endPos = subStr.find(end);
		if(endPos == -1 || endPos > subStr.length()) {
			return "";
		} else {
			string result(&subStr[0],endPos);
			return result;
		}
	}
	return "";
}
string extractStr(string text,string delimiter,int pos) {
	vector<string> list;
	Tokenize(text,list,delimiter);
	return list[pos];
}
string to_lower(string text) {
	int i;
	string buffer;
	for (i=0;i< text.length();i++) {
		if(isalpha(text[i]) != 0) {
			buffer+=tolower(text[i]);
		} else {
			buffer+=text[i];
		}
	}
	return buffer;
}

int checkUrlImage(string url) {
	string extn[] = {".jpg",".png",".jpeg",".gif",".webp"};
	int i;
	string temp = to_lower(url);
	for (i=0;i<5;i++) {
		if(temp.find(extn[i]) != -1) {
			return 1;
		}
	}
	return 0;
}
vector<Packet> assembleChuckedData(unsigned long int ackNo,vector<Packet> packetsRes) {
	int resIdx;
	vector<Packet> assembledData;
	set<unsigned long int> seqSet;
	for(resIdx=0;resIdx<packetsRes.size();resIdx++) {
		if((packetsRes[resIdx].ackNo == ackNo) && packetsRes[resIdx].payLoadLen > 0) {
				if(seqSet.count(packetsRes[resIdx].seqNo) == 0) {
					assembledData.push_back(packetsRes[resIdx]);
					seqSet.insert(packetsRes[resIdx].seqNo);
//					cout<<"Payload Len:: "<<packetsRes[resIdx].payLoadLen<<" -- "<<packetsRes[resIdx].seqNo<<endl;
				}
		}
	}
	sort(assembledData.begin(), assembledData.end(), compareBySeqNo);
	return assembledData;
}
string decodeData(string edata) {
	int currentPos = 0;
	unsigned long int totalSize = 0;
	unsigned long int currentSize=0;
	string buffer;
	string ddata;
	do{
		int pos = edata.find("\r\n",currentPos);
		string chunkSizeHx(&edata[currentPos],&edata[pos]);
		currentSize = cnvHexLongInt(chunkSizeHx);
		pos+=2;
		string temp(&edata[pos],&edata[pos+currentSize]);
		buffer = chunkSizeHx;
		if(buffer != "0") {
			ddata.append(temp);
			totalSize += temp.length();
			currentPos+=chunkSizeHx.length()+temp.length()+4;
		}
	}while(buffer != "0");
	return ddata;
}
string parseAssembledData(vector<Packet> assembledData) {
	int i;
	string data;
	unsigned long int totalSize = 0;
	for(int i=0;i<assembledData.size();i++) {
		if(i == 0) {
			int pos = assembledData[i].payload.find("\r\n\r\n")+ 4;
			if(pos != -1 || pos < assembledData[i].payload.length()) {
				string tempData(&assembledData[i].payload[pos],&assembledData[i].payload[assembledData[i].payload.length()]);
				data.append(tempData);
			}
		} else {
			data.append(assembledData[i].payload);
		}
	}
	string ddata = decodeData(data);
	return ddata;
}
string parseAssembledUnchunkedData(vector<Packet> assembledData) {
	int i;
		string data;
		unsigned long int totalSize = 0;
		for(int i=0;i<assembledData.size();i++) {
			if(i == 0) {
				int pos = assembledData[i].payload.find("\r\n\r\n")+ 4;
				if(pos != -1 || pos < assembledData[i].payload.length()) {
					string tempData(&assembledData[i].payload[pos],&assembledData[i].payload[assembledData[i].payload.length()]);
					data.append(tempData);
				}
			} else {
				string temp =assembledData[i].payload;
				data.append(temp );
			}
		}
		string ddata = (data);
		return ddata;
}
void getHTTPData(set<string> &packetSet,map<string,vector<Packet> > &consPackets) {
		vector<string> packetLst(packetSet.begin(),packetSet.end());
		vector<string> httpKey;
		map<string,string> httpOpData;
		int pktIdx;
		int httpCntr = 0;
		int rescounter = 0;
		for(pktIdx=0;pktIdx<packetLst.size();pktIdx++) {
			vector<Packet> packetsRes = consPackets[packetLst[pktIdx]+ " res"];
			sort(packetsRes.begin(), packetsRes.end(), compareBySeqNo); // not required to sort
			vector<Packet> packetsReq = consPackets[packetLst[pktIdx]+ " req"];
			sort(packetsReq.begin(), packetsReq.end(), compareBySeqNo);
			int reqIdx;
			for(reqIdx = 0;reqIdx<packetsReq.size();reqIdx++){
				if(packetsReq[reqIdx].payload.find(HTTP_REQ_SIG) !=-1) {
					httpCntr++;
					vector<string> lines;
					Tokenize(packetsReq[reqIdx].payload,lines,"\n");
					vector<string> word;
					Tokenize(lines[0],word," ");
					string url = word[1];
					string host = findSubStr(packetsReq[reqIdx].payload,"Host: ","\r");
					string op;
					int resIdx;
					map<unsigned long int,unsigned long int> resSeqNo;
					for(resIdx=0;resIdx<packetsRes.size();resIdx++) {
						unsigned long int temp = packetsReq[reqIdx].seqNo + packetsReq[reqIdx].payLoadLen;
						if((temp == (packetsRes[resIdx].ackNo)) && packetsRes[resIdx].payLoadLen != 0) {
//						if((packetsReq[reqIdx].ackNo == (packetsRes[resIdx].seqNo)) && packetsRes[resIdx].payLoadLen != 0) {

//							pair<map<unsigned long int,unsigned long int>::iterator,bool> resChk;
//							resChk = resSeqNo.insert(pair<unsigned long int,unsigned long int>(packetsRes[resIdx].seqNo,packetsRes[resIdx].seqNo));
//							if(resChk.second==true)
							{
								rescounter++;
								string payload = packetsRes[resIdx].payload;
								string statusLine = findSubStr(payload,"HTTP/","\r\n");
								if(!statusLine.empty()) {
									string status = extractStr(statusLine," ",1);
									/* length of the content in bytes */
									string contentLen = findSubStr(payload,"Content-Length: ","\r\n");
									if(contentLen.empty()) {
										string encoding = findSubStr(payload,"Transfer-Encoding: ","\r\n");
										if(encoding == "chunked") {
											vector<Packet> data = assembleChuckedData(packetsRes[resIdx].ackNo,packetsRes);
											string ddata = parseAssembledData(data);
											contentLen = intToStr(ddata.length());
										} else {
	//										cout<<"This is weird ????";
										}
									}
									op = to_lower(url)+" "+host+" "+status+" "+contentLen;
									httpKey.push_back(packetsReq[reqIdx].timestamp);
									httpOpData.insert(pair<string, string >(packetsReq[reqIdx].timestamp, op));
								}
							}
						}
					}
					/*if(rescounter == 0) {
						cout<<"This is weird !!!!!!";
					}*/
				}
			}
		}
		sort(httpKey.begin(), httpKey.end(), compareByTimestamp);
		int keyIdx;
		for(keyIdx =0;keyIdx<httpKey.size();keyIdx++) {
			cout<<httpOpData[httpKey[keyIdx]]<<endl;
		}
}
void getImageData(set<string> &packetSet,map<string,vector<Packet> > &consPackets) {

	vector<string> packetLst(packetSet.begin(),packetSet.end());
	vector<string> imageKey;
	map<string,string> imageOpData;
	int pktIdx;
	int imageCtr=0;
	for(pktIdx=0;pktIdx<packetLst.size();pktIdx++) {
		vector<Packet> packetsRes = consPackets[packetLst[pktIdx]+ " res"];
		sort(packetsRes.begin(), packetsRes.end(), compareBySeqNo); // not required to sort
		vector<Packet> packetsReq = consPackets[packetLst[pktIdx]+ " req"];
		sort(packetsReq.begin(), packetsReq.end(), compareBySeqNo);
		int reqIdx;
		for(reqIdx = 0;reqIdx<packetsReq.size();reqIdx++){
			if(packetsReq[reqIdx].payload.find(HTTP_REQ_SIG) !=-1) {
				vector<string> lines;
				Tokenize(packetsReq[reqIdx].payload,lines,"\n");
				vector<string> word;
				Tokenize(lines[0],word," ");
				string url = word[1];
				string op;
				int resIdx;
				map<unsigned long int,unsigned long int> resSeqNo;
				for(resIdx=0;resIdx<packetsRes.size();resIdx++) {
					unsigned long int temp = packetsReq[reqIdx].seqNo + packetsReq[reqIdx].payLoadLen;
					if((temp == (packetsRes[resIdx].ackNo)) && packetsRes[resIdx].payLoadLen != 0) {
//					if((packetsReq[reqIdx].ackNo == (packetsRes[resIdx].seqNo)) && packetsRes[resIdx].payLoadLen != 0) {

//						pair<map<unsigned long int,unsigned long int>::iterator,bool> resChk;
//						resChk = resSeqNo.insert(pair<unsigned long int,unsigned long int>(packetsRes[resIdx].seqNo,packetsRes[resIdx].seqNo));
//						if(resChk.second==true)
						{
							string payload = packetsRes[resIdx].payload;
							string statusLine = findSubStr(payload,"HTTP/","\r\n");
							if(!statusLine.empty()) {
								string status = extractStr(statusLine," ",1);
								if(status == "200") {
									if(checkUrlImage(url) == 1) {
										imageCtr++;
										string contentLen = findSubStr(payload,"Content-Length: ","\r\n");
										string ddata;
											string encoding = findSubStr(payload,"Transfer-Encoding: ","\r\n");
											if(encoding == "chunked") {
												vector<Packet> data = assembleChuckedData(packetsRes[resIdx].ackNo,packetsRes);
												ddata = parseAssembledData(data);
												contentLen = intToStr(ddata.length());
											} else {
												vector<Packet> data = assembleChuckedData(packetsRes[resIdx].ackNo,packetsRes);
												ddata = parseAssembledUnchunkedData(data);
											}

										string sizeHx = intToHx(strToInt(contentLen));
										string op = sizeHx+"\r\n"+ddata+"\r\n";
										imageKey.push_back(packetsReq[reqIdx].timestamp);
										imageOpData.insert(pair<string, string >(packetsReq[reqIdx].timestamp, op));
	//									}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	sort(imageKey.begin(), imageKey.end(), compareByTimestamp);
	int keyIdx;
	for(keyIdx =0;keyIdx<imageKey.size();keyIdx++) {
		cout<<imageOpData[imageKey[keyIdx]];
	}
	cout<<"0\r\n\r\n";
}

void parseData(vector<char> rawData,char* task) {
	WORD origLenStart = 12;
	WORD origLenEnd = 16;
	set<string> adSet;
	int curPos=0;
	int pktCnt=0;
	int tcpCnt=0;
	int udpCnt=0;
	int ipCnt=0;
	int connCnt=0;
	map<string,vector<Packet> > consPackets;
	set<unsigned long int> duplicateReqCk;
	set<unsigned long int> duplicateResCk;
	set<string> packetSet;
	char choice = task[0];
	while (rawData.size() > curPos) {
		pktCnt++;
		string origLenData(rawData.begin()+origLenStart+curPos,rawData.begin()+origLenEnd+curPos);//I
		int pktLen = cnvAsciiInt(origLenData,0);
		int totalLen = pktLen + RECORD_HEADER;
		string pkt(&rawData[curPos],&rawData[curPos+totalLen]); // I
		curPos +=totalLen; // I
		Packet packet = parsePacket(pkt);
		packet.no = pktCnt;
		if(packet.protocol == IP_PROTOCOL){
				ipCnt++;
		}
		if(packet.protocolType == UDP) {
			udpCnt++;
		} else if(packet.protocolType == TCP ) {
			tcpCnt++;
			string ad;
			if(packet.sourcePort == SERVER_PORT_HTTP || packet.sourcePort == SERVER_PORT_HTTPS) {
				ad = packet.destIp + packet.destPort + ":" + packet.sourceIp + packet.sourcePort;
			} else {
				ad = packet.sourceIp + packet.sourcePort + ":" + packet.destIp + packet.destPort;
			}
			if(choice != '1')
				consolidateTCPPkt(packetSet,consPackets,packet,duplicateReqCk,duplicateResCk);
			if(adSet.count(ad) == 0) {
				adSet.insert(ad);
				connCnt++;
			}
		}
	}
//	cout<< duplicateReqCk.size() <<" -- " << duplicateResCk.size()<<endl;
	switch(choice){
	case '1':
		cout<<pktCnt<<" "<<ipCnt<<" "<<tcpCnt<<" "<<udpCnt<<" "<<connCnt<<endl;
		break;
	case '2':
		getTcpData(packetSet,consPackets);
		break;
	case '3':
		getHTTPData(packetSet,consPackets);
		break;
	case '4':
		getImageData(packetSet,consPackets);
		break;
	default:
		cout<<"Please give a valid input";
	}
}
int main (int argc, char *argv[]) {
	vector<char> rawData = readFile();
	rawData.erase(rawData.begin(),rawData.begin()+GLOBAL_HEADER); // Removed GlobalHeader
	parseData(rawData,argv[1]);
  return 0;
}
