// Dan Levin
// 2009/08/20 demo.tcpspeaker.click
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



///////////////////////////
//tcps0 (simulating edge node a)
//////////////////////////

tun0
	-> CheckIPHeader
	-> StoreIPAddress(10.2.1.2, src)
	-> StoreIPAddress(10.2.1.1, dst)
	-> SetTCPChecksum
	-> SetIPChecksum
	-> tun1

tun1
	-> CheckIPHeader
	-> StoreIPAddress(10.2.0.2, src)
	-> StoreIPAddress(10.2.0.1, dst)
	-> GetIPAddress(16)
	-> SetTCPChecksum
	-> SetIPChecksum
	-> tun0

