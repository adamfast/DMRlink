##PROJECT: Motorola IPSC Reverse Engineering.
**PURPOSE:** Troubleshooting IPSC performance issues/possibly building an application gateway to extend IPSC beyond 15 repeaters.  
**IMPACT:** Potential concern from Motorla Solutions, as IPSC is a proprietary  
**METHOD:** Reverse engineering by pattern matching and process of elimination  
  
**PROPERTY:**  
This work represents the author's interpretation of the Motorola(tm) MOTOTRBO(tm) IPSC protocol. It is intended for academic purposes and not for commercial gain. It is not guaranteed to work, or be useful in any way, though it is intended to help IPSC users better understand, and thus maintain and operate, IPSC networks. This work is not affiliated with Motorola Solutions(tm), Inc. in any way. Motorola, Motorola Solutions, MOTOTRBO, ISPC and other terms in this document are registered trademarks of Motorola Solutions, Inc. Other registered trademark terms may be used. These are owned and held by their respective owners.  
  
**PRE-REQUISITE KNOWLEDGE:**  
This document assumes the reader is familiar with the concepts presented in the Motorola Solutions(tm), Inc. MOTOTRBO(tm) Systems Planner.  
  
**CONVENTIONS USED:**  
When communications exchanges are described, the symbols "->" and "<-" are used to denote the *direction* of the communcation. For example, "PEER -> MASTER" indicates communcation from the peer to the master. For each exchange outlined, the initiator of the particular communication will be on the left for the duration of the particular item being illustrated.  
  
###CONNECTION ESTABLISHMENT AND MAINTENANCE

**CORE CONCEPTS:**  
The IPSC system contains, essentially, two types of nodes: Master and Peer. Each IPSC network has exactly one master device and zero or more peers, recommended not to exceed 15. IPSC nodes may be a number of types of systems, such as repeaters, dispatch consoles, application software, etc. For example, the Motorola RDAC application acts as a peer in the IPSC network, though it doesn't operate as a repeater. The IPSC protocol supports many possible node types, and only a few have been identified. This document currently only explores repeaters - both Master and Peer, and their roles in the IPSC network.  
  
All IPSC communication is via UDP, and only the master needs a static IP address. Masters will operate behind NATs. A single UDP port, specified in programming the IPSC master device must be mapped through any NAT/stateful firewalls for the master, while peers require no special treatment.  
  
All nodes in an IPSC network maintain communication with each other at all times. The role of the master is merely to coordinate the joining of new nodes to the IPSC network. A functional IPSC network will continue without its master, as long as no new nodes need to join (or existing nodes need to re-join after a communications outage, etc.) This is one of the most important core concepts in IPSC, as it is central to the NAT traversal AND tracking of active peers.  
  
Each peer will send keep-alives to each other peer in the IPSC network at an interval specified in the devices "firewall open timer". The elegantly simple, yet effective approach of IPSC, uses this keep-alive to both open, and keep open stateful firewall and NAT translations between peers. Since each device handles all communications from a single UDP port, when a device sends a keep-alive or a registration request to another device, the source-destination address/port tuple for that communication is opened through stateful devices. The only requirement to maintain communication is that this timer be shorter than the UDP session timeout of network control elements (firewalls, packet shapers, NATs, etc.) Moreover, it does NOT appear that all devices in the IPSC network require the same setting for this. Each device would appear to maintain its own set timing without interference from different interval settings on other nodes in the IPSC.  
  
**KNOWN IPSC PACKET TYPES:**  
The following sections of this document will include various packet types. This is a list of currently known types and their meanings. Note: The names are arbitrarily chosen with the intention of being descriptive, and each is defined by what they've been "observed" to do in the wild.  

	CALL_CTL_1                = 0x61        |
	CALL_CTL_2                = 0x62        | Call control messages, exact use unknown
	CALL_CTL_3                = 0x63        |	
	XCMP_XNL         		  = 0x70		Control protocol messages
	GROUP_VOICE      		  = 0x80		This is a group voice call
	GROUP_DATA       		  = 0x83		This is a group data call
	PVT_DATA         		  = 0x84		This is a private data call
	RPT_WAKE_UP               = 0x85        Wakes up all repeaters on the IPSC
	MASTER_REG_REQ     		  = 0x90		Request registration with master (from peer, to master)
	MASTER_REG_REPLY          = 0x91		Master registration request reply (from master, to peer)
	PEER_LIST_REQ    		  = 0x92		Request peer list from master
	PEER_LIST_REPLY 	 	  = 0x93		Master peer list reply
	PEER_REG_REQ              = 0x94		Peer registration request
	PEER_REG_REPLY            = 0x95		Peer registration response
	MASTER_ALIVE_REQ          = 0x96		Master keep alive request (to master)
	MASTER_ALIVE_REPLY        = 0x97		Master keep alive reply (from master)
	PEER_ALIVE_REQ            = 0x98		Peer keep alive request (to peer)
	PEER_ALIVE_REPLY          = 0x99        Peer keep alive reply (from peer)
	DE_REG_REQ                = 0x9a        De-registraiton request (to master or all?)
	DE_REG_REPLY              = 0x9b        De-registration reply (from master or all?)



**AUTHENTICATION:**  
Most IPSC networks will be operated as "authenticated". This means that a key is used to create a digest of the packets exchanged in order to authenticate them. Each node in the IPSC network must have the authentication key programmed in order for the mechanism to work. The process is based on the SHA-1 digest protocol, where the "key" is a 20 byte hexadecimal *string* (if a shorter key is programmed, leading zeros are used to create a 20 byte key). The IPSC payload and the key are used to create the digest, of which only the most significant 10 bytes are used (the last 10 are truncated). This digest is appended to the end of the IPSC payload before transmission. An example is illustrated below:
  
	IPSC Registration Packet		Digest	
	90000000016a000080dc04030400	b0ec45f4c3f8fb0c0b1d
	

**CONNECTION CREATION:**  
The IPSC network truly "forms" when the first peer registers with the master. All peers register with the master in the same way, with a slight variation from the first peer. The registration and peer maintenance process is oulined below:  
  
  
	 * Peer Initiates connection to IPSC:
		 PEER -> MASTER		(peer sends a registration request to the master)
		 PEER <- MASTER		(master sends a registration reply)
		 PEER -> MASTER		(peer sends keep alive request to the master)
		 PEER <- MASTER		(peer receives keep alive response from the master)
			if the registration response indicated there is more than one peer (which would have been the peer) in the IPSC network...
		 PEER -> MASTER		(peer sends peer-list request to master)
		 PEER <- MASTER		(master sends a list of all peers in the IPSC by radio ID, their IP addresses and UDP ports)
		 PEER -> (ALL)		(peer begins exchanging keep alives with all other nodes in the IPSC based on the programmed interval)
	
	* Master updates the peer list to all nodes when there is a change:
		MASTER -> (PEERS)	(Master sends update list to each peer)
		...all peers begin registration and then keep-alives
		
	* ALL nodes continue sending/receiving keep alives to maintain the IPSC
	
**PACKET FORMATS:**  
  
REGISTRATION REQUESTS, KEEP-ALIVE REQUESTS AND RESPONSES:
The fields 'LINKING', 'FLAGS' and 'VERSION' are described in detail in the next section.

	TYPE(1 Byte) + SRC_ID (4 Bytes) + LINKING (1 Byte) + FLAGS (4 Bytes) + VERSION (4 Bytes) [+ AUTHENTICATION (10 Bytes)]
	90 0004C2C0 6A 000080DC 04030400 [AUTHENTICATION (10 Bytes)]

PEER LIST REQUEST:

	TYPE(1 Byte) + SRC_ID (4 Bytes) [+ AUTHENTICATION (10 Bytes)]
	92 0004C2C0 [AUTHENTICATION (10 Bytes)]

PEER LIST RESPONSE:

	TYPE(1 Byte) + SRC_ID (4 Bytes) + NUM_PEERS * (2 Bytes) + {PEER_ID, PEER_IP, PEER_PORT, PEER_LINKING}... [+ AUTHENTICATION (10 Bytes)]
	93 0004c2c0 002c* 
                 	 	00000001 6ccf7505 c351 6a
                		0004c2c3 d17271e9 c35a 6a
                 	   	0004c2c5 446716bb c35c 6a
                  	  	00c83265 a471c50c c351 6a
                                              		d66a94568d29357205c2


*Number of Peers, oddly formatted, stripping most significant non-zero digit seems to produce the correct value, such as 0x2c = 44, or 4 peers; or 0x6e = 110, or 10 peers

**CAPABILITIES: Bytes 6-14 (6-16 for master reg. reply):**
(Displayed in most to least significant bytes)

***LINKING STATUS: Byte 6***

	Byte 1 - BIT FLAGS:
	      xx.. .... = Peer Operational (01 only known valid value)
	      ..xx .... = Peer MODE: 00 - No Radio, 01 - Analog, 10 - Digital
	      .... xx.. = IPSC Slot 1: 10 on, 01 off 
	      .... ..xx = IPSC Slot 2: 10 on, 01 off

***SERVICE FLAGS: Bytes 7-10 (or 7-12)***

	Byte 1 - 0x00  	= Unknown
	Byte 2 - 0x00	= Unknown
	Byte 3 - BIT FLAGS:
	      x... .... = CBSK Message
	      .x.. .... = Unknwon - default to 0
	      ..x. .... = 3rd Party Application? (set by c-Bridge, SMARTPTT)
	      ...x xxxx = Unknown - default to 0
	Byte 4 = BIT FLAGS:
	      x... .... = XCMP/XNL - default to 0
	      .x.. .... = XCMP/XNL - default to 0
	      ..x. .... = XCMP/XNL - default to 0
	      ...x .... = Set if packets are authenticated
	      .... x... = Set if voice calls are supported
	      .... .x.. = Set if data calls are supported
	      .... ..x. = Unknown - default to 0
	      .... ...x = Set if master
	
	(the following only used in registration response from master)

	NUMBER of PEERS: 2 Bytes
	Byte 5 - 0x00	= Unknown
	Byte 6 - Number of Peers (not including us)

***PROTOCOL VERSION: Bytes 11-14 (or 12-16)***
(These are pure guesses based on repeater and c-Bridge code revisions)

	Bytes 1-2 - 0x04, 0x03 = Current version? (numbering scheme unknown)
	Bytes 3-4 = 0x04, 0x00 = Oldest supported version? (same as above)
  
**SAMPLE CODE:**  
  
*Sample Python3 code to generate the authentication digest:*  

	import binascii
	import hmac
	import hashlib
	
	def add_authentication (_payload, _key):
        _digest = binascii.unhexlify((hmac.new(_key,_payload,hashlib.sha1)).hexdigest()[:20])
        _full_payload = _payload + _digest
        return _full_payload
		
		PAYLOAD = binascii.unhexlify('90000000016a000080dc04030400')            # Registration packet
		KEY = binascii.unhexlify('0000000000000000000000000000000000012345')    # Key '12345'
		
		FULL_PAYLOAD = add_authentication(PAYLOAD, KEY)
		print(binascii.b2a_hex(FULL_PAYLOAD))
