##PROJECT: Motorola IPSC Reverse Engineering.
**PURPOSE:** Troubleshooting IPSC performance issues/possibly building an application gateway to extend IPSC beyond 15 repeaters.  
**IMPACT:** Potential concern from Motorla Solutions, as IPSC is a proprietary  
**METHOD:** Reverse engineering by pattern matching and process of elimination  
  
**PROPERTY:**  
This work represents the author's interpretation of the Motorola(tm) MOTOTRBO(tm) IPSC protocol. It is intended for academic purposes and not for commercial gain. It is not guaranteed to work, or be useful in any way, though it is intended to help IPSC users better understand, and thus maintain and operate, IPSC networks. This work is not affiliated with Motorola Solutions(tm), Inc. in any way. Motorola, Motorola Solutions, MOTOTRBO, ISPC and other terms in this document are registered trademarks of Motorola Solutions, Inc. Other registered trademark terms may be used. These are owned and held by their respective owners.  
  
**PRE-REQUISITE KNOWLEDGE:**  
This document assumes the reader is familiar with the concepts presented in the Motorola Solutions(tm), Inc. MOTOTRBO(tm) Systems Planner.  
  
**CONVENTIONS USED:**  
When communications exchanges are described, the symbols "->" and "<-" are used to donote the *direction* of the communcation. For example, "PEER -> MASTER" indicates communcation from the peer to the master. For each exchange outlined, the initiator of the particular communcation will be on the left for the duration of the particular item being illustrated.  
  
###CONNECTION ESTABLISHMENT AND MAINTENANCE

**CORE CONCEPTS:**  
The IPSC system contains, essentially, two types of nodes: Master and Peer. Each IPSC network has exactly one master device and zero or more peers, recommended not to exceed 15. IPSC nodes may be a number of types of systems, such as repeaters, dispatch consoles, application software, etc. For example, the Motorola RDAC applicaiton acts as a peer in the IPSC network, though it doesn't operate as a repeater. The IPSC protocol supports many possible node types, and only a few have been identified. This document currently only explores repeaters - both Master and Peer, and their roles in the IPSC network.  
  
All IPSC communication is via UDP, and only the master needs a static IP address. Masters will operate behind NATs. A single UDP port, specified in programming the IPSC master device must be mapped thorugh any NAT/stateful firewalls for the master, while peers require no special treatment.  
  
All nodes in an IPSC network maintain communication with each other at all times. The role of the master is merely to coordinate the joining of new nodes to the IPSC network. A functional IPSC network will continue without its master, as long as no new nodes need to join (or existing nodes need to re-join after a communications outage, etc.) This is one of the most important core concepts in IPSC, as it is central to the NAT traversal AND tracking of active peers.  
  
Each peer will send keep-alives to each other peer in the IPSC network at an interval specified in the devices "firewall open timer". The elegantly simple, yet effective approach of IPSC, uses this keep-alive to both open, and keep open stateful firewall and NAT translations between peers. Since each device handles all communications from a single UDP port, when a device sends a keep-alive or a registration request to another device, the source-destination address/port tuple for that commonication is opened through stateful devices. The only requirement to maintain communication is that this timer be shorter than the UDP session timeout of network control elements (firewalls, packet shapers, NATs, etc.) Moreover, it does NOT appear that all devices in the IPSC require the same setting for this. Each device would appear to maintain its own set timing without interference from different interval settings on other nodes in the IPSC.  
  
**KNOWN IPSC PACKET TYPES:**  
The following sections of this document will include various packet types. This is a list of currently known types and their meanings. Note: The names are arbitrarily chosen with the intention of being descriptive, and each is defined by what they've been "observed" to do in the wild.  

	RDAC_CTL         		  = 0x70		RDAC packets observed to use this type
	GROUP_VOICE      		  = 0x80		This is a group voice call
	GROUP_DATA       		  = 0x83		This is a group data call
	PVT_DATA         		  = 0x84		This is a private data call
	REG_REQ          		  = 0x90		Request registration with master
	REG_REPLY        		  = 0x91		Master registration request reply
	PEER_LIST_REQ    		  = 0x92		Request peer list from master
	PEER_LIST_REPLY 	 	  = 0x93		Master peer list reply
	PEER_KEEP_ALIVE_REQ		= 0x94		Peer keep alive request
	PEER_KEEP_ALIVE_REPLY	= 0x95		Peer keep alive response
	KEEP_ALIVE_REQ			  = 0x96		Master keep alive request (to maseter)
	KEEP_ALIVE_REPLY		  = 0x97		Master keep alive reply (from master)


**AUTHENTICATION:**  
Most IPSC netowrks will be operated as "authenticated". This means that a key is used to create a digest of the packets exchanged in order to authenticate them. Each node in the IPSC network must have the authentication key programmed in order for the mechanism to work. The process is based on the SHA-1 digest protocol, where the "key" is a 20 byte hexadecimal *string* (if a shorter key is programmed, leading zeros are used to create a 20 byte key). The IPSC payload and the key are used to create the digest, of which only the most significant 10 bytes are used (the last 10 are truncated). This digest is appended to the end of the IPSC payload before transmission. An example is illustrated below:  
  
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
		PEERn  -> NEW PEER	(each peer 'n' sends keep alive requests to the new peer)
		
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

	TYPE(1 Byte) + SRC_ID (4 Bytes) + NUM_PEERS* (2 Bytes) + {PEER_ID, PEER_IP, PEER_PORT, PEER_LINKING}... [+ AUTHENTICATION (10 Bytes)]
	93 0004c2c0 002c* 
                 	 	00000001 6ccf7505 c351 6a
                		0004c2c3 d17271e9 c35a 6a
                 	   	0004c2c5 446716bb c35c 6a
                  	  	00c83265 a471c50c c351 6a
                                              		d66a94568d29357205c2


*Number of Peers, oddly formatted, stripping most significant non-zero digit seems to produce the correct value, such as 0x2c = 44, or 4 peers; or 0x6e = 110, or 10 peers

CAPABILITIES (BYTES 6-14):

LINKING Status 1 byte
Byte 1 - BIT FLAGS:
      xx.. .... = Peer Operational (01 only known valid value)
      ..xx .... = MODE: 10 digital, 01 analog
      .... xx.. = IPSC Slot 1: 10 on, 01 off 
      .... ..xx = IPSC Slot 2: 10 on, 01 off

Service FLAGS: 4 bytes, Master replies = 6 bytes
Byte 1 - 0x00  	= Unknown
Byte 2 - 0x00	= Unknown
Byte 3 - BIT FLAGS:
      x... .... = Set to 1 if RDAC call
      .x.. .... = Unknwon - default to 0
      ..x. .... = 3rd Party Application? (set by c-Bridge, SMARTPTT)
      ...x xxxx = Unknown - default to 0
Byte 4 = BIT FLAGS:
      x... .... = RDAC related? - default to 0
      .x.. .... = RDAC related? - default to 0
      ..x. .... = RDAC related? - default to 0
      ...x .... = Set if packets are authenticated
      .... x... = Set if voice calls are supported
      .... .x.. = Set if data calls are supported
      .... ..x. = Unknown - default to 0
      .... ...x = Set if master
   (the following only used in registration response from master)
NUMBER of PEERS: 2 Bytes
Byte 5 - 0x00	= Unknown
Byte 6 - Number of Peers (not including us)

Protocol VERSION: 4 Bytes (These are pure guesses based on repaeter and c-Bridge code revisions)
Bytes 1-2 - 0x04, 0x03 = Current version? (numbering scheme unknown)
Bytes 3-4 = 0x04, 0x00 = Oldest supported version? (same as above)
  
**SAMPLE CODE:**  
  
*Sample Python3 code to genearate the authentication digest:*  

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


**Example Python3 code to register to a master, exchange keep alives, reqest, recieve and decode the peer list:**

	import socket
	import binascii
	import hmac
	import hashlib
	
	# Data structure for holding IPSC information
	NETWORK = {
    	'IPSC1': {
        	'LOCAL': {
            	'DESCRIPTION': 'K0USY Lecompton, KS - Master',
            	'MODE': b'\x6A',
            	'PORT': 50001,
            	'RADIO_ID': binascii.unhexlify('00000001'),
            	'AUTH_KEY': binascii.unhexlify('0000000000000000000000000000000000012345')
			},
      		'MASTER': {
				'IP': '24.143.49.121',
    			'MODE': b'\x6A',
				'PORT': 50000,
				'RADIO_ID': '',
        		},
        	'PEERS': [  # each list entry will be a dictionary for IP, RADIO ID and PORT
            	#{'IP': '100.200.1.1', 'PORT': 50000, 'RADIO_ID': b'\x00\x00\x00\xFF'},
        	]        
    	}
	}
	
	# Known IPSC Message Types
	RDAC_CTL              = b'\x70'
	GROUP_VOICE           = b'\x80'
	GROUP_DATA            = b'\x83'
	PVT_DATA              = b'\x84'
	REG_REQ               = b'\x90'
	REG_REPLY             = b'\x91'
	PEER_LIST_REQ         = b'\x92'
	PEER_LIST_REPLY       = b'\x93'
	PEER_KEEP_ALIVE_REQ   = b'\x94'
	PEER_KEEP_ALIVE_REPLY = b'\x95'
	KEEP_ALIVE_REQ        = b'\x96'
	KEEP_ALIVE_REPLY      = b'\x97'
	
	# IPSC information
	IPSC_TS_BOTH   = b'\x6A'             # Both Timeslots IPSC enabled
	IPSC_OP_VER    = b'\x04\x03'         # 0x04, 0x03 -- seems to be current version of IPSC
	IPSC_OLD_VER   = b'\x04\x00'         # 0x04, 0x02 -- oldest version of IPSC suppoerted
	IPSC_FLAGS     = b'\x00\x00\x80\xDC' # Just accept this... it works, we know some of the pieces
	
	#********** FUNCTIONS THAT WE WILL USE
	
	# function to send a payload to a defined socket
	def send_auth_packet (_dest_addr, _dest_port, _socket, _data, _key):
		_hash = binascii.unhexlify((hmac.new(_key,_data,hashlib.sha1)).hexdigest()[:20])
		print("==> Sending Authenticated Packet")
		print("    Destination IP:", _dest_addr)
    	print("    Destination UDP Port:", _dest_port)
    	print("    Raw Packet:", binascii.b2a_hex(_data + _hash))
    	_socket.sendto((_data+_hash), (_dest_addr, _dest_port))
    	return
		
		# Note: This function ignores authentiation information!!!
	def receive_packet(_socket):
    	_data = (_socket.recv(1024))
    	_peer_id = str(int(binascii.b2a_hex(_data[2:5]), 16))
    	_mode = binascii.b2a_hex(_data[5:6])
    	print('<== Response Recieved from Radio ID:', _peer_id)
    	print('    Raw Packet:', binascii.b2a_hex(_data))
    	# Parse returned information
    
		_packettype = (_data[0:1])
		_sock = 'IPSC1'
    
    	if (_packettype == REG_REQ):
        	print(" >> This is a registration packet")
			
    	elif (_packettype == REG_REPLY):
        	print(" >> This is a registration reply packet")
        
		elif (_packettype == PEER_LIST_REPLY):
        	print(">> This packet is a peer list from the master")
        	_num_peers = int(str(int(binascii.b2a_hex(_data[5:7]), 16))[1:])
        	# print('>>There are', binascii.b2a_hex(_data[5:7]), 'peers in this IPSC (RAW)')
        	print('>> There are', _num_peers, 'peers in this IPSC')
        	for i in range(7, (_num_peers*11)+7, 11):
            NETWORK[_sock]['PEERS'].append({
            	'RADIO_ID': binascii.b2a_hex(_data[i:i+4]), 
            	'IP':       binascii.b2a_hex(_data[i+4:i+8]), 
            	'PORT':     binascii.b2a_hex(_data[i+8:i+10]), 
           	 	'MODE':     binascii.b2a_hex(_data[i+10:i+11])
            })
			print_peer_list('IPSC1')        
    
    	return _data, _packettype
		
	def print_peer_list(_ipsc_network):
		print(NETWORK[_ipsc_network]['LOCAL']['DESCRIPTION'])
		for dictionary in NETWORK[_ipsc_network]['PEERS']:
		hex_address = dictionary['IP']
		hex_port = dictionary['PORT']
    	hex_radio_id = dictionary['RADIO_ID']
    	hex_mode = dictionary['MODE']
    
		address = [int(hex_address[0:2], 16), int(hex_address[2:4], 16), int(hex_address[4:6], 16), int(hex_address[6:8], 16)]
    	port = int(hex_port, 16)
    	radio_id = int(hex_radio_id, 16)
    
		print(address[0],".",address[1],".",address[2],".",address[3],"\t", sep='', end='')
    	print(port, radio_id, hex_mode, sep='\t')
		return
		
	#********** THE ACTUAL MEAT
		
	# Create a socket to conetact IPSC Network #1
	ipsc1_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	ipsc1_sock.bind(('', NETWORK['IPSC1']['LOCAL']['PORT']))
	ipsc1_sock.setblocking(0)
	ipsc1_sock.settimeout(60)
	
	CTL_SUFFIX              = (IPSC_TS_BOTH + IPSC_FLAGS + IPSC_OP_VER + IPSC_OLD_VER)
	REG_REQ_PACKET          = (REG_REQ + NETWORK['IPSC1']['LOCAL']['RADIO_ID'] + CTL_SUFFIX)
	KEEP_ALIVE_PACKET        = (KEEP_ALIVE_REQ + NETWORK['IPSC1']['LOCAL']['RADIO_ID'] + CTL_SUFFIX)
	PEER_LIST_REQ_PACKET    = (PEER_LIST_REQ + NETWORK['IPSC1']['LOCAL']['RADIO_ID'])
	
	# Send registration packet
	send_auth_packet(NETWORK['IPSC1']['MASTER']['IP'], NETWORK['IPSC1']['MASTER']['PORT'], ipsc1_sock, REG_REQ_PACKET, NETWORK['IPSC1']['LOCAL']['AUTH_KEY'])
	receive_packet(ipsc1_sock)
	
	# Send keep alive packet
	send_auth_packet(NETWORK['IPSC1']['MASTER']['IP'], NETWORK['IPSC1']['MASTER']['PORT'], ipsc1_sock, KEEP_ALIVE_PACKET, NETWORK['IPSC1']['LOCAL']['AUTH_KEY'])
	receive_packet(ipsc1_sock)
		
	# Request peer list from master
	send_auth_packet(NETWORK['IPSC1']['MASTER']['IP'], NETWORK['IPSC1']['MASTER']['PORT'], ipsc1_sock, PEER_LIST_REQ_PACKET, NETWORK['IPSC1']['LOCAL']['AUTH_KEY'])
	receive_packet(ipsc1_sock)
	
	ipsc1_sock.close
