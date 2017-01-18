/*
 *  DNSResolver.cpp
 *  Authors: Zachary Gill and Viet Duong
 *  Version Date: March 4th, 2016
 */

#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <ctype.h>
#include <map>
#include <string>
#include <vector>
#include <time.h>
#include <stdexcept>
#include <algorithm>

using namespace std;

// Header for entire DNS packet struct
typedef struct{
  u_int16_t id;
  u_int8_t rd:1;
  u_int8_t tc:1;
  u_int8_t aa:1;
  u_int8_t opcode:4;
  u_int8_t qr:1;
  u_int8_t rcode:4;
  u_int8_t cd:1;
  u_int8_t ad:1;
  u_int8_t z:1;
  u_int16_t qcount;
  u_int16_t ancount;
  u_int16_t authcount;
  u_int16_t addcount; 
} dnshdr;

// Query Info (Type and Class) struct
typedef struct{
	u_int16_t qType;
	u_int16_t qClass;
} dnsQryInfo;

// Record Info (Type, class, ttl, rdLength)
typedef struct{
	u_int16_t rType;
	u_int16_t rClass;
	u_int32_t ttl;
	u_int16_t rdLength;
} r_info;

// Resource Record struct, has name, data, and the info
typedef struct{
	char* name;
	r_info* info;
	char* rdata;
}dnsResRecord;

// Special version of Resource Record that contains a last checked time for TTL calculations
typedef struct{
	dnsResRecord resRecord;
	time_t lastChecked;
}cacheRecord;

// Query Struct: Name and info section
typedef struct{
	char* name;
	dnsQryInfo* question;
} dnsQuery;

// Cache is organzied where key is name of record, everything else stored a vector of records.
map<string, vector<cacheRecord>> cache;


int printquery(int pos, char* buf);
int decodename(char* buf, int pos, char* dst);
void encodename(char* src, char* dst);
void printHeader(dnshdr head);
int diffDecode(char* src, char* buffer, int pos, char* dst);
void addCache(char* response, int &size, dnshdr copyHeader);
void clearCache();
dnsResRecord searchCache(char* key);
unsigned char* ReadName(unsigned char* reader,unsigned char* buffer,int* count, bool netStyle);


// add Cache adds to the cache all records containted in the current buffer pointed to by response.
// Size is the size of the query. Passed as argument since it is easier than another looping algo.
void addCache(char* response, int &size, dnshdr copyHeader)
{
	printf("adding to cache\n");
	
	if(ntohs(copyHeader.ancount) < 0 && ntohs(copyHeader.authcount) < 0 && ntohs(copyHeader.addcount) < 0){
		printf("No records to add\n");
		return;
	}

	// Skip to answer  section.
	char* current = response + size;
	int ret = 0;

	u_int32_t IP;

	// Loop through all answer records. For each, add to cache.
	for(int i = 0; i < ntohs(copyHeader.ancount); i++)
	{
		cacheRecord currentRec;
		currentRec.resRecord.name = (char *)malloc(512);
		currentRec.resRecord.info = (r_info *)malloc(10);

		time_t nowTime = 0;

		// Getting the record to add later, name of record is same name used as key for map.

		currentRec.resRecord.name = (char *)ReadName((unsigned char*)current, (unsigned char*)response, &ret, true);

		current += ret + 1;

		// Getting info
		memcpy(currentRec.resRecord.info, current, 10);
	
		current += 10;

		// Getting rdata

		// If IP, do this.
		if(currentRec.resRecord.info->rType == 1)
	         {
			current -= 1;
                        // If type IP, then it should be 4 bytes long according to standard: IP is stored as an unsigned 32 bit.
                        currentRec.resRecord.rdata = (char*)malloc(4);
                        int j;
                        for(j = 0; j < 4; j++){
                                currentRec.resRecord.rdata[j] = current[j];
                        }
                        // End data string.
                        currentRec.resRecord.rdata[ntohs(currentRec.resRecord.info->rdLength)]='\0';
                	memcpy(&IP, currentRec.resRecord.rdata, 4);
		}
		else{
				currentRec.resRecord.rdata = (char*)malloc(512);
				ret = diffDecode(current, response, ret, currentRec.resRecord.rdata);
				current += ret;
		}


		// Adding to map
		string key(currentRec.resRecord.name);
		cache.insert(pair<string, vector<cacheRecord> >(key, vector<cacheRecord>()));
		nowTime = time(NULL);
		currentRec.lastChecked = nowTime;
		cache[key].push_back(currentRec);
	}
	if(ntohs(copyHeader.ancount) == 0){
		current += 13;
	}

	vector<char*> auth;
	// Loop through all auth records. 
	for(int i = 0; i < ntohs(copyHeader.authcount); i++)
	{
		cacheRecord currentRec;

		currentRec.resRecord.name = (char *)malloc(512);
		currentRec.resRecord.info = (r_info *)malloc(10);
		currentRec.resRecord.rdata = (char *)malloc(1024);

		time_t nowTime = 0;

		// Getting the record to add later, name of record is same name used as key for map.

		currentRec.resRecord.name = (char *)ReadName((unsigned char*)current, (unsigned char*)response, &ret, true);
		current += ret + 1;

		// Getting info
		memcpy(currentRec.resRecord.info, current, 10);
		current += 10;

		// Getting rdata
		currentRec.resRecord.rdata = (char *)ReadName((unsigned char*)current, (unsigned char *)response, &ret, false);
		current += ret;

		// Adding to map
	
	//	auth.push_back(currentRec.resRecord.name);
		string key(currentRec.resRecord.name);
		cache.insert(pair<string, vector<cacheRecord> >(key, vector<cacheRecord>()));
		nowTime = time(NULL);
		currentRec.lastChecked = nowTime;
		cache[key].push_back(currentRec);
		
	}

	// Loop through all add records
	// Loop through all add records. For each, add to cache.
	for(int i = 0; i < ntohs(copyHeader.addcount); i++)
	{
		cacheRecord currentRec;
		currentRec.resRecord.name = (char *)malloc(512);
		currentRec.resRecord.info = (r_info *)malloc(10);

		time_t nowTime = 0;

		// Getting the record to add later, name of record is same name used as key for map.

		currentRec.resRecord.name = (char *)ReadName((unsigned char*)current, (unsigned char*)response, &ret, true);
	//	if(i < auth.size())
	//		currentRec.resRecord.name = auth[i];
		current += ret + 1;

		// Getting info
		memcpy(currentRec.resRecord.info, current, 10);
	
		current += 10;

		// Getting rdata
		// If IP, do this.
		if(ntohs(currentRec.resRecord.info->rType) == 1)
	         {
			current -= 1;
                        // If type IP, then it should be 4 bytes long according to standard: IP is stored as an unsigned 32 bit.
                        currentRec.resRecord.rdata = (char*)malloc(4);
                        int j;
                        for(j = 0; j < 4; j++){
                                currentRec.resRecord.rdata[j] = current[j];
			 }
                        // End data string.
                        // currentRec.resRecord.rdata[ntohs(currentRec.resRecord.info->rdLength)]='\0';
                	//memcpy(&IP, currentRec.resRecord.rdata, 4);
		}
		else{
				currentRec.resRecord.rdata = (char*)malloc(512);
				ret = diffDecode(current, response, ret, currentRec.resRecord.rdata);
				current += ret;
		}


		// Adding to map
		string key(currentRec.resRecord.name);
		cache.insert(pair<string, vector<cacheRecord> >(key, vector<cacheRecord>()));
		nowTime = time(NULL);
		currentRec.lastChecked = nowTime;
		cache[key].push_back(currentRec);
	}


}

// Instead of simply using [] operator in rest of program, use helper function to change time, etc.

dnsResRecord searchCache(char* key)
{
	string test(key);
	dnsResRecord ret;
	ret.rdata = (char*)malloc(1);
	printf("Searching for %s\n", key);
	// See if key is in map, get that list if so.
	try{
		auto list = cache.at(test);
		// go through list until the type requested is found. Still update records we pass TTL.
		for(auto it = list.begin(); it != list.end(); ++it)
		{

			
			(*it).resRecord.info->ttl -= htons((time(NULL) - ((*it).lastChecked)));
			(*it).lastChecked = time(NULL);
		
	
			if((*it).resRecord.info->ttl <= 0){
				printf("Remove old ttl record\n");
				list.erase(it);
				continue;
			}
			// Only worry about NS or A type records
			if((*it).resRecord.info->rType <= 2){
				printf("Found record in cache to use\n");
				
				return (*it).resRecord;
			}
		}


	}catch(const out_of_range &exc)
	{
		printf("Not in cache\n");
		ret.rdata = "\0";
		return ret;
	}
}


// Go through entire cache/map and free all that needs to be freed. Then delete the cache.
void clearCache()
{
	//Need to free each rdata, rinfo, rname of each record.
	for(auto rec: cache) // every pair
	{
		for(auto record: rec.second) // every record in vector of records
		{
			free(record.resRecord.name);
			free(record.resRecord.rdata);
			free(record.resRecord.info);
		}
	}
}

// Reply Helper does most of the work of the Resolver. It takes:
// socket to send/rec on, the client addr, the server addr, the previous query that was sent, and size of query
// This function calls itself when needed. This is called once per send to a server.
void replyHelper(int sockfd, struct sockaddr_in client, struct sockaddr_in server, char* prevQuery, int size)
{
	socklen_t length = sizeof(server);
	char reply[5000];
	int temp = recvfrom(sockfd, reply, 5000, 0, (struct sockaddr*)&server, &length);	
	printf("Response from root was %d byes\n", temp);
	int newSize = temp;
	if(temp < 0){
		perror("Error\n");
		return;
	}
	dnshdr replyHeader;
	memcpy(&replyHeader, reply, 12);

	printf("Response:\n");
	printf("%d Questions.\n", ntohs(replyHeader.qcount));
	printf("%d Answers. \n", ntohs(replyHeader.ancount));
	printf("%d Authority. \n", ntohs(replyHeader.authcount));
	printf("%d Addtional. \n", ntohs(replyHeader.addcount));

	// Skip past query + header for pointer.
	char* current = reply + size; 

	// Have answer, send to client, return.
	if(ntohs(replyHeader.ancount) > 0)
	{
		addCache(reply, size, replyHeader);
		printf("Sending answer to client\n");
		socklen_t len = sizeof(client);
		int sending = sendto(sockfd, reply, newSize, 0, (struct sockaddr*)&client, len);
		if (sending < 0)
			perror("Error sending answer to client\n");
		return;
	}
	
	// Send RCODE if any to client. Return.
	if(ntohs(replyHeader.rcode) != 0)
	{
		printf("Rcode from server\n");
		socklen_t len = sizeof(client);
		int sending = sendto(sockfd, reply, newSize, 0, (struct sockaddr*)&client, len);
		if (sending < 0)
			perror("Error sending answer to client\n");
		return;
	}
	// Skipping past auth section. Want additional section for
	// IP.
	int i, ret;
	ret = 0;

	uint32_t IP;
	int ipFound;
	ipFound = 0;

	struct sockaddr_in nextServer;
	nextServer.sin_port = htons(53);
	nextServer.sin_family = AF_INET;


	dnsResRecord throwOut;

	throwOut.name = (char *)malloc(512);
	throwOut.info = (r_info *)malloc(10);
	throwOut.rdata = (char *)malloc(1024);
	// Skip empty answer section
	//current += 13;

	for(i = 0; i < ntohs(replyHeader.authcount); i++)
	{

		// Copy non-variable stuff into throwOut.

		throwOut.name = (char *)ReadName((unsigned char*)current, (unsigned char *)reply, &ret, true);

		current += ret+1;

		memcpy(throwOut.info, current, 10); 
		current += 10;
	
		// Copy data into rdata, skip that many spots ahead.
		throwOut.rdata = (char *)ReadName((unsigned char*)current, (unsigned char *)reply, &ret, true);
		current += ret;
	}
	
	// Didn't find IP yet, keep going. Look through additional
	dnsResRecord addRec;
	addRec.name = (char *)malloc(512);
	addRec.info = (r_info *)malloc(10);
	for(i = 0; i < ntohs(replyHeader.addcount); i++)
	{
		if(ipFound > 0)
			break;
		addRec.name = (char *)ReadName((unsigned char*)current, (unsigned char *)reply, &ret, true);


		// Check if additional is in cache. If so, can use that IP instead
	/*	auto returnRec = searchCache(addRec.name);
		
		if(returnRec.rdata[0] != '\0')
		{
			printf("Using cached additional record\n");
			for(int b = 0; b < 4; b++)
				printf("val of return data %d\n", returnRec.rdata[b]);

			memcpy(&IP, returnRec.rdata, 4);
			ipFound = 1;
			break;
		}
		*/
		current += ret+1;
		// Copy non-variable stuff into addRec.

		memcpy(addRec.info, current, 10);
		current += 10; 		

		// If type is IPv4, save that IP for later
		if(ntohs(addRec.info->rType) == 1)
		{
			current -= 2;
			// If type IP, then it should be 4 bytes long according to standard: IP is stored as an unsigned 32 bit.
			printf("Found IP!\n");
			addRec.rdata = (char*)malloc(4);
			int j;
			printf("Putting IP in\n");
			for(j = 0; j < 4; j++){
				addRec.rdata[j] = current[j];
			}
			// End data string.
			printf("Ending string\n");
			addRec.rdata[4]='\0';
			current += 4;
			ipFound = 1;
			printf("Copy into IP\n");
			memcpy(&IP, addRec.rdata, 4);

		}

		else{
			if(ntohs(addRec.info->rType) == 28){
				current += 16; // Skipping the size of AAAA
			}
			else{
				addRec.rdata = (char*)malloc(512);
				
				ret = diffDecode(current, reply, ret, addRec.rdata);
				current += ret;
			}
		}
	}
	// Get to send to next server.
	if(ipFound > 0){
	
		addCache(reply, size, replyHeader);
		printf("Sending to next server\n");
		nextServer.sin_addr.s_addr = IP;
		socklen_t length = sizeof(nextServer);
		int sent = sendto(sockfd, prevQuery, size, 0, (struct sockaddr*)&nextServer, length);
		if(sent < 0){
			perror("Error sending to next server\n");
			return;
		}
		replyHelper(sockfd, client, nextServer, prevQuery, sent);
		free(addRec.rdata);
		free(addRec.name);
		free(addRec.info);
		return;
	}

	// If no IP, type was not A. Since we don't need to handle
	// CNAMEs or what not, just returning an RCODE to user.
	replyHeader.rcode = 4;
	printf("Sending not_implemented to client\n");


	memcpy(&reply, &replyHeader, sizeof(replyHeader));	

	socklen_t len = sizeof(client);
	int sending = sendto(sockfd, reply, newSize, 0, (struct sockaddr*)&client, len);
	if (sending < 0)
		perror("Error sending not implemented to client\n");
	return;



}

// Returns current location in packet.
int diffDecode(char* src, char* buffer, int pos, char* dst)
{
	int i, p, jump, off;
	int ret = 0;
	p = 0;
	jump = 0;
	// Finding pointers
	while(src[0] != 0)
	{
		if((src[0]>= 192)) // Meaning: 1100 0000 or larger, pointer
		{
			printf("Found pointer\n");
			//Larger importance byte starts at 256 for val. 
			//so multiply that in for offset, add in the 
			//next byte, take away the value of a pointer 
			//sequence 41925.

			off = *(src)*256 + *(src + 1) - 49125; 
			src = buffer + off - 1;
			jump = 1;
			
		}
		else{
			dst[p] = src[0];
			p++;
		}
		src++;
		if(jump == 0)
			ret++;
	}
	dst[p] = '\0'; // End the String
	if(jump > 0)
		ret++;

	// Turning numbers into .
	// If not printable, turn into .
	for(i = 0; i < strlen(dst); i++)
	{
		if(isprint(dst[i]) == 0)
			dst[i] = '.';
	}

	return ret;
}


int main(int argc, char* argv[])
{
	int port = 0;
	if(argc < 2){
		printf("Error: No port number entered as command line arg.\n");
		return 1;
	}
	else{
		// Port checking
		port = atoi(argv[1]);
		if(port <= 0 || port > 65535){
			printf("Invalid port\n");
			return 1;
		}	
		printf("entered %d\n", port);
	}

	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	if(sockfd< 0){
		printf("Error creating socket\n");
		return 1;
	}

	struct sockaddr_in serveraddr, clientaddr;
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(port);
	serveraddr.sin_addr.s_addr = INADDR_ANY;

	int e = bind(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr));
	if (e < 0)
	{
		printf("Bind error\n");
		return 1;
	}

	struct sockaddr_in rootServer;
	rootServer.sin_port = htons(53);
	rootServer.sin_addr.s_addr = inet_addr("199.7.83.42"); // Root Server L
	rootServer.sin_family = AF_INET;


	while(1)
	{
		socklen_t len = sizeof(clientaddr);
		char line[5000];
		int n = recvfrom(sockfd, line, 5000, 0, (struct sockaddr*)&clientaddr, &len);
		printf("Got this much: %d\n", n);
		if(n == -1){
			perror("Error\n");
		}
		
		// Copy what we got from client
		
		dnshdr clientHeader;
		memcpy(&clientHeader, line, 12);		
	
		char decode[256];
		char encode[256];
		int ret = decodename(line, 12, decode);
		printf("Decode query %s\n", decode);

		char *decodeSpec = (char *)malloc(256);
		int tempRet = 0;
		char * current = line + 12;
		decodeSpec = (char *)ReadName((unsigned char*)current, (unsigned char*)line, &tempRet, true);


		auto test = searchCache(decodeSpec);

		printf("Decoded using ReadName %s\n", decodeSpec);

		free(decodeSpec);

		dnsQryInfo clientQryInfo;
		dnsQuery clientQry;
		clientQry.question = &clientQryInfo;
		encodename(decode, encode);
		// Copy the information about the query to a struct.		
		clientQryInfo.qType = line[12 + ret + 1];	
		clientQryInfo.qClass = line[12 + ret + 3];
		clientQry.name = encode;

		if(test.rdata[0] != '\0'){
			
			clientHeader.ancount = htons(1);
			clientHeader.rd = 0;
			clientHeader.qr = 1;
			
			char toSend[5000];
			memcpy(&toSend, &clientHeader, 11);
			
			// Copy rest
			strncpy(&toSend[12], clientQry.name, ret);
			toSend[12 + ret + 1] = clientQryInfo.qType;
			toSend[12 + ret + 3] = clientQryInfo.qClass;

			
			char* tempSend = toSend + 16 + ret;


			memcpy(tempSend, test.name, strlen(test.name));
			
			tempSend += strlen(test.name) + 2;

			memcpy(tempSend, test.info, 9);
			tempSend += 9;

			memcpy(tempSend, test.rdata, 4);

		
			printf("Cached answer sending to client\n");
			int temp = sendto(sockfd, toSend, n + sizeof(test) + 6, 0, (struct sockaddr*)&clientaddr, len);

			if(temp < 0)
				perror("Error sending cache answer to client\n");
	
			continue;
		}
		// Keeping the rest in the struct for safe keeping, but only sending the last few bytes.

		if(clientQryInfo.qType == 0x0001 && clientQryInfo.qClass == 0x0001)
		{
			// Unset recursion bit
			clientHeader.rd = 0;
			printHeader(clientHeader);
			clientHeader.qr = 0; // Tell root it is a query
			
			// Forward request to root name server
			char toSend[5000];
			memcpy(&toSend, &clientHeader, 12);
		
			// Copy rest using strcat
			strncpy(&toSend[12], clientQry.name, ret);
			toSend[12 + ret + 1] = clientQryInfo.qType;
			toSend[12 + ret + 3] = clientQryInfo.qClass;

			int temp = sendto(sockfd, toSend, n, 0, (struct sockaddr*)&rootServer, sizeof(rootServer));	
			printf("sent to root %d bytes \n", temp);
			if(temp == -1){
				perror("Error\n");
				continue;
			}
			// After getting response, do stuff with it.
			// Using a helper function to make things easier
			replyHelper(sockfd, clientaddr, rootServer, toSend, n);
			continue;
		}
		else{
			
			clientHeader.rd = 0;
			clientHeader.qr = 1;
			clientHeader.rcode = 4;
			memcpy(&line, &clientHeader, sizeof(clientHeader));
			int temp = sendto(sockfd, line, n, 0, (struct sockaddr*)&clientaddr, len);
			printf("Not Supported, told client. Sent this many bytes: %d\n", temp);
		}
	}
	
	return 0;
}

void printHeader(dnshdr head)
{
	printf("ID: %d\n", head.id);
	printf("rd: %d\n", head.rd);	
	printf("tc: %d\n", head.tc);
	printf("aa: %d\n", head.aa);
	printf("opcode: %d\n", head.opcode);
	printf("qr: %d\n", head.qr);
	printf("qcount: %d\n", head.qcount);
	printf("ancount: %d\n", head.ancount);
	printf("authcount: %d\n", head.authcount);
	printf("addcount: %d\n", head.addcount);
}

void encodename(char* src, char* dst){
  int i=0;
  int pos=0;
  while(src[i]!='\0'){
    if(src[i]=='.'){
      dst[pos]=i-pos;
      pos=i+1;
    } else {
    dst[i+1]=src[i];
    }
    ++i;
  }
  dst[pos]=i-pos;
  dst[i+1]=0;
}

int decodename(char* buf, int pos, char* dst){
  int start=pos;
  int ret=0;
  int j=0;
  while(buf[pos]!=0){
    if((buf[pos]&0xC0)==0xC0){ //pointer
      if(ret==0){
	ret=(pos-start)+2;
      }
      pos = (buf[pos]&(~0xC0))<<8+buf[pos];
    } else {
      int len = buf[pos];
      if(j!=0){
	dst[j]='.';
	j++;
      }
      for(int i=0; i<len; i++){
	dst[j+i]=buf[pos+i+1];
      }
      j+=len;
      pos+=len+1;
    }
  }
  dst[j]='\0';
  if(ret==0){
    ret=(pos-start)+1;
  }
  return ret;
}




int printquery(int pos,char* buf){
  char name[256];
  int namelen = decodename(buf,pos,name);
  int dnstype = buf[pos+namelen+1];
  int dnsclass = buf[pos+namelen+3];
  printf("Query: %s\t%d\t%d\n",name,dnstype,dnsclass);
  return pos+namelen+4;
}
// Read name is a modified diffDecode, created since our use of decodename was not fully implemented.
// reader is current position, buffer is the entire packet, count is the return int of decodename poiting towards end of name, and netstyle lets function know to fully convert to human readable or not.
// This was created after some research online on better ways to read record names.
unsigned char* ReadName(unsigned char* reader,unsigned char* buffer,int* count, bool netStyle)
{
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;
 
    *count = 1;
    name = (unsigned char*)malloc(256);
 
    name[0]='\0';
 
    //read the names in 3www6google3com format
    while(*reader!=0)
    {
        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++]=*reader;
        }
 
        reader=reader+1;
 
        if(jumped==0) *count = *count + 1; //if we havent jumped to another location then we can count up
    }
 
    name[p]='\0'; //string complete
    if(jumped==1) 
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }
 
    //now convert 3www6google3com0 to www.google.com
	if(!netStyle){ 
		for(i=0;i<(int)strlen((const char*)name);i++)
		{
			if(isprint(name[i]) == 0)
				name[i] = '.';
   		}
        }
    return name;
}
