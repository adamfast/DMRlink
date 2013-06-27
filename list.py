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