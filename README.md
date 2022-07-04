# Klaytn_vm_setting

Introduction
This document is to reproduce the Klaytn consensus message monitoring experiment environment. Let us describe briefly our experimental setup for the simple controlled experiment involving seven CNs. Each CN operates on separate virtual machines (VMs) and all of their peer-to-peer sessions go over the common software Open vSwitch (OvS). One POX controller is connected to the software switch. Then we captured all packets per network interface we defined (tap1, tap2 and so on). 

Figure1. Overview of our SDN-based Klaytn network analysis framework

	
Consensus message monitoring
consensus message
Consensus node(CN) of Klaytn is built atop the Istanbul Byzantine Fault Tolerance(IBFT) protocol. IBFT is a consensus protocol for blockchain that guarantees immediate finality. There are four distinct types of consensus messages in IBFT: pre-prepare, prepare, commit, and roundchange. 
In terms of implementation, several types of messages are used to maintain the Klaytn system, including transaction msg, messages for the rlpx protocol, and consensus message. Consensus message refers to a message type utilized by CNs to achieve consensus. Each consensus message contains consensus message type, sender’s address, sender’s signature, message including round number and so on. All of these messages are encrypted with keys that are unique to each TCP session. To obtain the round number and message type, I extracted keys and decrypted the data.
consensus message monitoring
Monitoring consensus messages represents the list of messages received per round for each CN. If one of the CNs becomes the proposer at a particular round number, it will not receive a preprepare message. 
I utilized Grafana's dashboard to represent the number of messages received from each CN.

Figure 2. Grafana dashboard example


File description
/klaytn_pox/data_processing.py
This file does many things as described below:
creating a txt file from a pcap file that contains every packet sent during a tcp session.
identifying a secret key for every tcp session.
decrypt each RLPx frame.
record the outcome in a MySQL database.
This python file uses Crypto, sha3, snappy, rlp library to decode each frame.
You need to modify this file based on your system. This file is used in your host machine.
/klaytn_pox/data_processing_header.py
		This file describes some useful functions for data_processing.py.
You need to modify this file based on your system. This file is used in your host machine.
/klaytn_pox/VM_script/rlpx.go
The Klaytn kcn file is created using this file. I slightly altered the code in order to obtain the secret key. Don't forget to run "make" once the original Klaytn rlpx has been converted to this. Your virtual machine uses this file. Also, make a SecData directory and you need to modify some code based on your system.
/klaytn_pox/VM_ script/script.sh
This file transmits the secret key extracted from rlpx.go to the host machine. You need to make a ‘secrets’ directory in your host machine and modify this code based on your system.
Data processing
Data Structure
We decrypt and decode the received RLPx messages. Figure 3 shows the RLPx message structure. We use the counter-mode symmetric key decryption with AES. And the Snappy compression is used to decompress messages.

Figure3. RLPx message structure

Data collection
I used the open-source PacketSorter library to gather data. It sorts packets ordered by sequence number and any duplicated and empty messages are eliminated from the output pcap file. 
Also, this program attaches to each network interface. In order to capture all incoming and outgoing packets, I run PacketSorter at tap1.
I used the Scapy package to read pcap files in Python.
Data decryption
The data processing.py file handles data decryption. The frame is decrypted using Crypto and the sha3 library. And the frame is decompressed using Snappy.
Software Prerequisites
This project can run only on Ubuntu.
Software Installation
Things that you should keep in mind before the installment.
There are many things that must be installed manually, so it will take some time to handle everything. The intended reader is Klaytn developers, so simple steps may be omitted. If you are familiar with Klaytn node implementation using virtual machines (VMs), it may be of great assistance. Additionally, I just figured I'd run 7 CNs. As a result, numerous variables are set to 7. This is something you should keep in mind and adjust for your project.
 	Above all, Google is our best friend. 
Installation process
Kernel-based Virtual Machine(KVM)
Klaytn CN is constructed using Virtual Machine.
POX
Without POX, the source and destination mac addresses of each path had to be hardcoded. This is accomplished automatically by POX, which is very convenient.
Open vSwitch(OVS)
Virtual switch for inter-VM communication.
Go(Installed in VM)
The implementation of Klaytn is based on GO.
Klaytn CN(Installed in VM)
make(Installed in VM)
PacketSorter application
It is an open-source library that records each TCP flow and has a number of options for customizing the pcap file, including the ability to filter packets by sequence number and delete empty packets.
MySQL
Database
I used Grafana, which is simple to connect to MySQL and utilized for visualization.
Detailed steps
KVM installation
https://phoenixnap.com/kb/ubuntu-install-kvm
OVS installation
apt-get install openvswitch-switch
Configure the OVS
* x represents the vm number.
sudo ovs-vsctl add-br br0

sudo ovs-vsctl add-port br0 tap{x} -- set Interface tap{x} type=internal ofport={x}

sudo ip link set tap{x} up 
Verify
sudo ovs-vsctl show
sudo ovs-ofctl show br0
Connect to VMs
VM{x} connects to Bridged Network, tap{x}. Configure the two VMs as follow 
On VM{x} (use ifconfig to see VM’s network interface):
sudo nano /etc/network/interfaces
edit this file as below:
auto enp0s3
iface enp0s3 inet static
address 10.0.0.1
netmask 255.0.0.0
network 10.0.0.0
broadcast 10.255.255.255
Then, restart the networking.
				sudo ip addr flush enp0s3
sudo systemctl restart networkings 
Two network interfaces may be connected to the VM. One should be connected to the tap, and the other should be connected to the NAT, enabling Internet communication.
Pox Installation
Download the POX folder from the git
				https://noxrepo.github.io/pox-doc/html/#installing-pox
Need to open taps
				sudo ip link set tap{x} up
Update openflow rule in the OVS automatically. 
cd pox
./pox.py --verbose forwarding.l2_learning
Now, you can ping between VMs. Inside the VM, ping to each other so that you make sure that you installed correctly.
PacketSorter application
Installation:
https://github.com/rickyzhang82/PacketSorter
Save pcap file(remember {x} always stands for the VM number). This code captures packets passing through tap1, meaning the source or destination address is CN{x}. 
cd ~
mkdir tcpflow{x} 
sudo ~/PacketSorter/build/bin/PacketSorter -i tap{1} -o ~/tcpflow{x} -x
What host machine needs to do
Make directories
				mkdir ~/data_collection
				mkdir ~/secrets
git clone https://github.com/klaytn/klaytn.git
run data_processing
// you need to modify something in data_processing.py and data_processing_header.py according to your system. I stated what you have to do in “TODO”.
				./auto_data_processing.sh
What VMs need to do (You must implement this procedure for each VM. Therefore, I recommend that you execute the first VM flawlessly and then simply duplicate it.)
Install GO
wget https://go.dev/dl/go1.17.5.linux-amd64.tar.gz

sudo rm -rf /usr/local/go && go tar -C /usr/local -xzf go1.17.5.linux-amd64.tar.gz

export PATH=$PATH:/usr/local/go/bin

go version
Install Klaytn
git clone https://github.com/klaytn/klaytn.git
cd klaytn/build
make (for ‘make’, make sure that you have gcc and make installed. If not, sudo apt install gcc && sudo apt install make)
After this, you can follow the link below and you can skip STEP0 and the extracting part of the STEP1.
https://docs.klaytn.com/node/service-chain/getting-started/4nodes-setup-guide
After this, you can follow the link below and you can skip STEP0 and the extracting part of the STEP1.
git clone https://github.com/NetSP-KAIST/klaytn_pox.git
Modify some code
cd ~
mkdir SecData
cd ~/klaytn_pox/VM_script
				sudo nano rlpx.go 
				// Search for TODO and modify them based on your system.
				cp ~/klaytn_pox/VM_script/rlpx.go  ~/klaytn/networks/p2p/rlpx.go
				cd ~/klaytn
				make
				cp ~/klaytn_pox/VM_script/script.sh ~/
// follow the link below to make auto-authentication with your host machine				https://alvinalexander.com/linux-unix/how-use-scp-without-password-backups-copy/
// Modify script.sh based on your system.
nano ~/script.sh
// I recommend you to run script.sh all the time.
./script.sh
Setting is done. Run klaytn CN.
kcnd start
Grafana installation
https://grafana.com/docs/grafana/latest/setup-grafana/installation/debian/	
		
Future works
A script that automates the installation of Klaytn CNs would be of great assistance to those who wish to conduct network experiments with Klaytn CNs.



