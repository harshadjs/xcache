#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <libgen.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <string>
#include <vector>

#include <sys/types.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include "Xsocket.h"
#include "xcontrold.hh"
#include "dagaddr.hpp"

#define DEFAULT_NAME "controller0"
#define APPNAME "xcontrold"

char *hostname = NULL;
char *ident = NULL;

RouteState route_state;

void timeout_handler(int signum)
{
	UNUSED(signum);

	if (route_state.hello_seq < route_state.hello_lsa_ratio) {
		// send Hello
		//sendHello();
		route_state.hello_seq++;
	} else if (route_state.hello_seq == route_state.hello_lsa_ratio) {
		// it's time to send LSA
		//sendLSA();
		// reset hello req
		route_state.hello_seq = 0;
	} else {
		syslog(LOG_ERR, "hello_seq=%d hello_lsa_ratio=%d", route_state.hello_seq, route_state.hello_lsa_ratio);
	}
	// reset the timer
	signal(SIGALRM, timeout_handler);
	ualarm((int)ceil(HELLO_INTERVAL*1000000),0);
}

// send Hello message (1-hop broadcast)
// Send my AD and my HID to the directly connected neighbors
int sendHello()
{
	/* Message format (delimiter=^)
		message-type{Hello=0 or LSA=1}
		source-AD
		source-HID
	*/

    ControlMessage msg(CTL_HELLO);

    msg.append(route_state.myAD);
    msg.append(route_state.myHID);

	Xsendto(route_state.sock, msg.c_str(), msg.size(), 0, (struct sockaddr *)&route_state.ddag, sizeof(sockaddr_x));

	return 1;
}

int sendRoutingTable(std::string destHID, std::map<std::string, RouteEntry> routingTable)
{
	/* Message format (delimiter=^)
		message-type{Hello=0 or LSA=1}
		source-AD
		source-HID
	*/

    ControlMessage msg(CTL_ROUTING_TABLE);

    msg.append(route_state.myAD);
    msg.append(destHID);

    msg.append(route_state.ctl_seq);

    msg.append((int)routingTable.size());

	map<string, RouteEntry>::iterator it;
  	for (it = routingTable.begin(); it != routingTable.end(); it++)
    {
        msg.append(it->second.dest);
        msg.append(it->second.nextHop);
        msg.append(it->second.port);
        msg.append(it->second.flags);
  	}

	Xsendto(route_state.sock, msg.c_str(), msg.size(), 0, (struct sockaddr *)&route_state.ddag, sizeof(sockaddr_x));

	route_state.ctl_seq = (route_state.ctl_seq + 1) % MAX_SEQNUM;

	return 1;
}

// process a LinkStateAdvertisement message
int processLSA(string msg)
{
	/* Procedure:
		0. scan this LSA (mark AD with a DualRouter if there)
		1. filter out the already seen LSA (via LSA-seq for this dest)
		2. update the network table
		3. rebroadcast this LSA
	*/

	// 0. Read this LSA
    int msgType, isDualRouter, lsaSeq, numNeighbors, neighborPort;
    string destAD, destHID, neighborAD, neighborHID;

    ControlMessage ctlMsg(msg);
    ctlMsg.read(msgType);

    ctlMsg.read(isDualRouter);
    ctlMsg.read(destAD);
    ctlMsg.read(destHID);

  	// See if this LSA comes from AD with dualRouter
  	if (isDualRouter == 1)
  		route_state.dual_router_AD = destAD;

  	// First, filter out the LSA originating from myself
  	if (destHID == route_state.myHID)
  		return 1;

    ctlMsg.read(lsaSeq);

  	// 1. Filter out the already seen LSA
	map<std::string, NodeStateEntry>::iterator it;
	it = route_state.networkTable.find(destHID);

    // If this originating HID has been known (i.e., already in the networkTable)
	if (it != route_state.networkTable.end())
    {
        // If this LSA already seen, ignore this LSA; do nothing
  	  	if ((lsaSeq <= it->second.seq) && ((it->second.seq - lsaSeq) < 10000))
  			return 1;

  		// For now, delete this dest HID entry in networkTable (... we will re-insert the updated entry shortly)
  		route_state.networkTable.erase (it);
  	}

    ctlMsg.read(numNeighbors);

	// 2. Update the network table
	NodeStateEntry entry;
	entry.dest = destHID;
	entry.seq = lsaSeq;
	entry.num_neighbors = numNeighbors;

  	int i;
 	for (i = 0; i < numNeighbors; i++)
    {
        ctlMsg.read(neighborAD);
        ctlMsg.read(neighborHID);
        ctlMsg.read(neighborPort);

 		// fill the neighbors into the corresponding networkTable entry
        NeighborEntry neighbor_entry;
        neighbor_entry.AD = neighborAD;
        neighbor_entry.HID = neighborHID;
        neighbor_entry.port = neighborPort;
 		entry.neighbor_list.push_back(neighbor_entry);
 	}

	route_state.networkTable[destHID] = entry;
	route_state.calc_dijstra_ticks++;

	if (route_state.calc_dijstra_ticks >= CALC_DIJKSTRA_INTERVAL)
    {
		syslog(LOG_INFO, "Calcuating shortest paths\n");

        map<std::string, NodeStateEntry>::iterator it1;
        for (it1=route_state.networkTable.begin(); it1 != route_state.networkTable.end(); it1++)
        {
            map<std::string, RouteEntry> routingTable;
            populateRoutingTable(it1->second.dest, routingTable);
            sendRoutingTable(it1->second.dest, routingTable);
        }

		route_state.calc_dijstra_ticks = 0;
	}

	return 1;
}

void populateRoutingTable(std::string srcHID, std::map<std::string, RouteEntry> &routingTable)
{
	// first, clear the current routing table
	routingTable.clear();

 	map<std::string, NodeStateEntry>::iterator it1;
  	for ( it1=route_state.networkTable.begin() ; it1 != route_state.networkTable.end(); it1++ ) {

 		// filter out an abnormal case
 		if(it1->second.num_neighbors == 0 || (it1->second.dest).empty() ) {
 			route_state.networkTable.erase (it1);
 		}
  	}

 	map<std::string, NodeStateEntry> table;
	table = route_state.networkTable;

  	for ( it1=route_state.networkTable.begin() ; it1 != route_state.networkTable.end(); it1++ ) {
 		// initialize the checking variable
 		it1->second.checked = false;
 		it1->second.cost = 10000000;
  	}

	// compute shortest path
	// initialization
	string myHID, tempHID;
	myHID = srcHID;
	route_state.networkTable[myHID].checked = true;
	route_state.networkTable[myHID].cost = 0;
	table.erase(myHID);

	vector<NeighborEntry>::iterator it2;
	for ( it2=route_state.networkTable[myHID].neighbor_list.begin() ; it2 < route_state.networkTable[myHID].neighbor_list.end(); it2++ ) {

		tempHID = (*it2).HID.c_str();

        if (route_state.networkTable.find(tempHID) != route_state.networkTable.end())
        {
            route_state.networkTable[tempHID].cost = 1;
            route_state.networkTable[tempHID].prevNode = myHID;
        }
        else
        {
            NodeStateEntry entry;
            entry.dest = tempHID;
            entry.seq = route_state.networkTable[myHID].seq;
            entry.num_neighbors = 1;

            NeighborEntry neighbor_entry;
            //neighbor_entry.AD = neighborAD;
            neighbor_entry.HID = myHID;
            neighbor_entry.port = 0;
            entry.neighbor_list.push_back(neighbor_entry);
            entry.cost = 1;
            entry.prevNode = myHID;

            route_state.networkTable[tempHID] = entry;
        }
	}

	// loop
	while (!table.empty()) {
		int minCost = 10000000;
		string selectedHID, tmpHID;
		for ( it1=table.begin() ; it1 != table.end(); it1++ ) {
			tmpHID = it1->second.dest;
			if (route_state.networkTable[tmpHID].cost < minCost) {
				minCost = route_state.networkTable[tmpHID].cost;
				selectedHID = tmpHID;
			}
  		}
		if(selectedHID.empty()) {
			return;
		}

  		table.erase(selectedHID);
  		route_state.networkTable[selectedHID].checked = true;

 		for ( it2=route_state.networkTable[selectedHID].neighbor_list.begin() ; it2 < route_state.networkTable[selectedHID].neighbor_list.end(); it2++ ) {
			tempHID = (*it2).HID.c_str();
			if (route_state.networkTable[tempHID].checked != true) {
				if (route_state.networkTable[tempHID].cost > route_state.networkTable[selectedHID].cost + 1) {
					route_state.networkTable[tempHID].cost = route_state.networkTable[selectedHID].cost + 1;
					route_state.networkTable[tempHID].prevNode = selectedHID;
				}
			}
		}
	}

	string tempHID1, tempHID2;
	int hop_count;
	// set up the nexthop
  	for ( it1=route_state.networkTable.begin() ; it1 != route_state.networkTable.end(); it1++ ) {

  		tempHID1 = it1->second.dest;
  		if ( myHID.compare(tempHID1) != 0 ) {
  			tempHID2 = tempHID1;
  			hop_count = 0;
  			while (route_state.networkTable[tempHID2].prevNode.compare(myHID)!=0 && hop_count < MAX_HOP_COUNT) {
  				tempHID2 = route_state.networkTable[tempHID2].prevNode;
  				hop_count++;
  			}
  			if(hop_count < MAX_HOP_COUNT) {
  				routingTable[tempHID1].dest = tempHID1;
                routingTable[tempHID1].nextHop = tempHID2;

                for ( it2=route_state.networkTable[myHID].neighbor_list.begin() ; it2 < route_state.networkTable[myHID].neighbor_list.end(); it2++ )
                {
                    if ((*it2).HID == tempHID2)
                        routingTable[tempHID1].port = (*it2).port;
                }
  			}
  		}
  	}

	printRoutingTable(srcHID, routingTable);
}

void printRoutingTable(std::string srcHID, std::map<std::string, RouteEntry> &routingTable)
{
	syslog(LOG_INFO, "Routing table for %s", srcHID.c_str());
  	map<std::string, RouteEntry>::iterator it1;
  	for ( it1=routingTable.begin() ; it1 != routingTable.end(); it1++ ) {
  		syslog(LOG_INFO, "Dest=%s, NextHop=%s, Port=%d, Flags=%u", (it1->second.dest).c_str(), (it1->second.nextHop).c_str(), (it1->second.port), (it1->second.flags) );
  	}
}

void initRouteState()
{
	// make the dest DAG (broadcast to other routers)
	Graph g = Node() * Node(BHID) * Node(SID_XROUTE);
	g.fill_sockaddr(&route_state.ddag);

	syslog(LOG_INFO, "xroute Broadcast DAG: %s", g.dag_string().c_str());

	// read the localhost AD and HID
	if ( XreadLocalHostAddr(route_state.sock, route_state.myAD, MAX_XID_SIZE, route_state.myHID, MAX_XID_SIZE, route_state.my4ID, MAX_XID_SIZE) < 0 ) {
		syslog(LOG_ALERT, "Unable to read local XIA address");
		exit(-1);
	}

	// make the src DAG (the one the routing process listens on)
	struct addrinfo *ai;
	if (Xgetaddrinfo(NULL, SID_XROUTE, NULL, &ai) != 0) {
		syslog(LOG_ALERT, "unable to create source DAG");
		exit(-1);
	}
	memcpy(&route_state.sdag, ai->ai_addr, sizeof(sockaddr_x));

	route_state.num_neighbors = 0; // number of neighbor routers
	route_state.lsa_seq = 0;	// LSA sequence number of this router
	route_state.hello_seq = 0;  // hello seq number of this router
	route_state.hello_lsa_ratio = (int32_t) ceil(LSA_INTERVAL/HELLO_INTERVAL);
	route_state.calc_dijstra_ticks = 0;

	route_state.ctl_seq = 0;	// LSA sequence number of this router

	route_state.dual_router_AD = "NULL";
	// mark if this is a dual XIA-IPv4 router
	if( XisDualStackRouter(route_state.sock) == 1 ) {
		route_state.dual_router = 1;
		syslog(LOG_DEBUG, "configured as a dual-stack router");
	} else {
		route_state.dual_router = 0;
	}

	// set timer for HELLO/LSA
	signal(SIGALRM, timeout_handler);
	ualarm((int)ceil(HELLO_INTERVAL*1000000),0); 	
}

void help(const char *name)
{
	printf("\nusage: %s [-l level] [-v] [-c config] [-h hostname]\n", name);
	printf("where:\n");
	printf(" -l level    : syslog logging level 0 = LOG_EMERG ... 7 = LOG_DEBUG (default=3:LOG_ERR)");
	printf(" -v          : log to the console as well as syslog");
	printf(" -h hostname : click device name (default=router0)\n");
	printf("\n");
	exit(0);
}

void config(int argc, char** argv)
{
	int c;
	unsigned level = 3;
	int verbose = 0;

	opterr = 0;

	while ((c = getopt(argc, argv, "h:l:v")) != -1) {
		switch (c) {
			case 'h':
				hostname = strdup(optarg);
				break;
			case 'l':
				level = MIN(atoi(optarg), LOG_DEBUG);
				break;
			case 'v':
				verbose = LOG_PERROR;
				break;
			case '?':
			default:
				// Help Me!
				help(basename(argv[0]));
				break;
		}
	}

	if (!hostname)
		hostname = strdup(DEFAULT_NAME);

	// load the config setting for this hostname
	set_conf("xsockconf.ini", hostname);

	// note: ident must exist for the life of the app
	ident = (char *)calloc(strlen(hostname) + strlen (APPNAME) + 4, 1);
	sprintf(ident, "%s:%s", APPNAME, hostname);
	openlog(ident, LOG_CONS|LOG_NDELAY|LOG_LOCAL4|verbose, LOG_LOCAL4);
	setlogmask(LOG_UPTO(level));
}

int main(int argc, char *argv[])
{
	int selectRetVal, n;
    size_t found, start;
    socklen_t dlen;
    char recv_message[1024];
    sockaddr_x theirDAG;
    fd_set socks;
    struct timeval timeoutval;
	vector<string> routers;

	config(argc, argv);
	syslog(LOG_NOTICE, "%s started on %s", APPNAME, hostname);

   	// open socket for route process
   	route_state.sock=Xsocket(AF_XIA, SOCK_DGRAM, 0);
   	if (route_state.sock < 0) {
   		syslog(LOG_ALERT, "Unable to create a socket");
   		exit(-1);
   	}

   	// initialize the route states (e.g., set HELLO/LSA timer, etc)
   	initRouteState();

   	// bind to the src DAG
   	if (Xbind(route_state.sock, (struct sockaddr*)&route_state.sdag, sizeof(sockaddr_x)) < 0) {
   		Graph g(&route_state.sdag);
   		syslog(LOG_ALERT, "unable to bind to local DAG : %s", g.dag_string().c_str());
		Xclose(route_state.sock);
   		exit(-1);
   	}

	while (1) {
		FD_ZERO(&socks);
		FD_SET(route_state.sock, &socks);
		timeoutval.tv_sec = 0;
		timeoutval.tv_usec = 2000; // every 0.002 sec, check if any received packets

		selectRetVal = select(route_state.sock+1, &socks, NULL, NULL, &timeoutval);
		if (selectRetVal > 0) {
			// receiving a Hello or LSA packet
			memset(&recv_message[0], 0, sizeof(recv_message));
			dlen = sizeof(sockaddr_x);
			n = Xrecvfrom(route_state.sock, recv_message, 1024, 0, (struct sockaddr*)&theirDAG, &dlen);
			if (n < 0) {
	    			perror("recvfrom");
			}

			string msg = recv_message;
			start = 0;
			found=msg.find("^");
  			if (found!=string::npos) {
  				string msg_type = msg.substr(start, found-start);
  				int type = atoi(msg_type.c_str());
				switch (type) {
					case CTL_LSA:
  						processLSA(msg);
						break;
					default:
						break;
				}
  			}
		}
    }

	return 0;
}