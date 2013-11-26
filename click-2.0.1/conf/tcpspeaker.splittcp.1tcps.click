// Dan Levin
//
//
//              -------------------------------
// TCP Host --> eth0  tcps0   <->   tcps1  eth1 <- TCP Host
//              -------------------------------
//

ChatterSocket(TCP, 5010);
ControlSocket(TCP, 5011);

tun0  :: KernelTun(10.2.0.1/24, DEVNAME tun0) 
tun1  :: KernelTun(10.2.1.1/24, DEVNAME tun1) 

tcps0 :: TCPSpeaker(FIN_AFTER_TCP_FIN 1, RCVBUF 0x66666666, WINDOW_SCALING 3, FIN_AFTER_UDP_IDLE 0, IDLETIME 20, VERBOSITY $VERB0);


///////////////////////////
//tcps0 (simulating edge node a)
//////////////////////////

tun0
	-> CheckIPHeader
	-> StoreIPAddress(10.2.1.2, src)
	-> StoreIPAddress(10.2.1.1, dst)
	-> GetIPAddress(16)
	-> [0]tcps0

tcps0[0]
	-> Unqueue
	-> TCPtoUDP
	-> SetUDPChecksum
	-> SetIPChecksum
	-> tun1


///////////////////////////
//tcps1 (simulating edge node b)
//////////////////////////

tun1
	-> CheckIPHeader
	-> [1]tcps0

tcps0[1]
	-> StoreIPAddress(10.2.0.2, src)
	-> StoreIPAddress(10.2.0.1, dst)
	-> GetIPAddress(16)
	-> SetTCPChecksum
	-> SetIPChecksum
	-> tun0
