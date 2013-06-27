from __future__ import print_function
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from twisted.internet import task
import binascii
import hmac
import hashlib


# Data structure for holding IPSC information
NETWORK = {
    'IPSC1': {
        'LOCAL': {
            'DESCRIPTION': 'IPSC Network #1',
            'MODE': b'\x6A',
            'FLAGS': b'\x00\x00\x80\xDC',
            'PORT': 50001,
            'RADIO_ID': binascii.unhexlify('00000001'),
            'AUTH_KEY': binascii.unhexlify('0000000000000000000000000000000000000001')
        },
        'MASTER': {
            'IP': '1.1.1.1',
            'MODE': b'\x6A',
            'PORT': 50000,
            'RADIO_ID': '',
        },
        'PEERS': [  # each list entry will be a dictionary for IP, RADIO ID and PORT
            #{'IP': '100.200.1.1', 'PORT': 50000, 'RADIO_ID': b'\x00\x00\x00\xFF'},
        ]      
    },
    'IPSC2': {
        'LOCAL': {
            'DESCRIPTION': 'IPSC Network #1',
            'MODE': b'\x6A',
            'FLAGS': b'\x00\x00\x80\xDC',
            'PORT': 50002,
            'RADIO_ID': binascii.unhexlify('00000002'),
            'AUTH_KEY': binascii.unhexlify('0000000000000000000000000000000000000022')
        },
        'MASTER': {
            'IP': '2.2.2.2',
            'MODE': b'\x6A',
            'PORT': 50000,
            'RADIO_ID': '',
        },
        'PEERS': [  # each list entry will be a dictionary for IP, RADIO ID and PORT
            #{'IP': '100.200.1.1', 'PORT': 50000, 'RADIO_ID': b'\x00\x00\x00\xFF'},
        ]        
    },
    'IPSC3': {
        'LOCAL': {
            'DESCRIPTION': 'IPSC Network #1',
            'MODE': b'\x6A',
            'FLAGS': b'\x00\x00\x80\xDC',
            'PORT': 50003,
            'RADIO_ID': binascii.unhexlify('00000003'),
            'AUTH_KEY': binascii.unhexlify('0000000000000000000000000000000000000333')
        },
        'MASTER': {
            'IP': '3.3.3.3',
            'MODE': b'\x6A',
            'PORT': 50000,
            'RADIO_ID': '',
        },
        'PEERS': [  # each list entry will be a dictionary for IP, RADIO ID and PORT
            #{'IP': '100.200.1.1', 'PORT': 50000, 'RADIO_ID': b'\x00\x00\x00\xFF'},
        ]        
    },
    'IPSC4': {
        'LOCAL': {
            'DESCRIPTION': 'IPSC Network #1',
            'MODE': b'\x6A',
            'FLAGS': b'\x00\x00\x80\xDC',
            'PORT': 50004,
            'RADIO_ID': binascii.unhexlify('00000004'),
            'AUTH_KEY': binascii.unhexlify('0000000000000000000000000000000000004444')
        },
        'MASTER': {
            'IP': '4.4.4.4',
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
RPT_WAKE_UP           = b'\x85'
MASTER_REG_REQ        = b'\x90' # FROM peer TO master
MASTER_REG_REPLY      = b'\x91' # FROM master TO peer
PEER_LIST_REQ         = b'\x92'
PEER_LIST_REPLY       = b'\x93'
PEER_REG_REQUEST      = b'\x94' # Peer registration request
PEER_REG_REPLY        = b'\x95' # Peer registration reply
MASTER_ALIVE_REQ      = b'\x96' # FROM peer TO master
MASTER_ALIVE_REPLY    = b'\x97' # FROM master TO peer
PEER_ALIVE_REQ        = b'\x98' # Peer keep alive request
PEER_ALIVE_REPLY      = b'\x99' # Peer keep alive reply

# IPSC Version Information
IPSC_OP_VER    = b'\x04\x03'         # 0x04, 0x03 -- seems to be current version of IPSC
IPSC_OLD_VER   = b'\x04\x00'         # 0x04, 0x02 -- oldest version of IPSC suppoerted
IPSC_VER       = IPSC_OP_VER + IPSC_OLD_VER


def hashed_packet(key, data):
    hash = binascii.unhexlify((hmac.new(key,data,hashlib.sha1)).hexdigest()[:20])
    return (data + hash)
    
def print_peer_list(_ipsc_network):
  print('\t', _ipsc_network['LOCAL']['DESCRIPTION'])
  for dictionary in _ipsc_network['PEERS']:
    hex_address = dictionary['IP']
    hex_port = dictionary['PORT']
    hex_radio_id = dictionary['RADIO_ID']
    hex_mode = dictionary['MODE']
    
    address = [int(hex_address[0:2], 16), int(hex_address[2:4], 16), int(hex_address[4:6], 16), int(hex_address[6:8], 16)]
    port = int(hex_port, 16)
    radio_id = int(hex_radio_id, 16)
    
    print ('\t', address[0],address[1],address[2],address[3], sep='.', end='\t')
    print (port, radio_id, sep=':', end=' ')
    print ("IPSC Mode:", hex_mode)
  print()

class IPSC(DatagramProtocol):
    
    def __init__(self, *args, **kwargs):
        if len(args) == 1:
            self._config = args[0]
            args = ()
            self.TS_FLAGS             = (self._config['LOCAL']['MODE'] + self._config['LOCAL']['FLAGS'])
            self.MASTER_REG_REQ_PKT   = (MASTER_REG_REQ + self._config['LOCAL']['RADIO_ID'] + self.TS_FLAGS + IPSC_VER)
            self.MASTER_ALIVE_PKT     = (MASTER_ALIVE_REQ + self._config['LOCAL']['RADIO_ID'] + self.TS_FLAGS + IPSC_VER)
            self.PEER_LIST_REQ_PKT    = (PEER_LIST_REQ + self._config['LOCAL']['RADIO_ID'])
            self.PEER_REG_REPLY_PKT   = (PEER_REG_REPLY + self._config['LOCAL']['RADIO_ID'] + IPSC_VER)
            self.PEER_ALIVE_REQ_PKT   = (PEER_ALIVE_REQ + self._config['LOCAL']['RADIO_ID'] + self.TS_FLAGS)
            self.PEER_ALIVE_REPLY_PKT = (PEER_ALIVE_REPLY + self._config['LOCAL']['RADIO_ID'] + self.TS_FLAGS)
        else:
            print("Unexpected arguments found.")

    def masterKeepalive(self):
        master_alive_packet = hashed_packet(self._config['LOCAL']['AUTH_KEY'], self.MASTER_ALIVE_PKT)
        self.transport.write(master_alive_packet, (self._config['MASTER']['IP'], self._config['MASTER']['PORT']))
        print("->> Master Keep Alive Sent To:\t", self._config['MASTER']['IP'],":", self._config['MASTER']['PORT'], "\n")

    def startProtocol(self):
        print ("*** config: %s" % self._config)
        print ()
        print ("*** Starting up IPSC Client and Registering to the Master ***")
        reg_packet = hashed_packet(self._config['LOCAL']['AUTH_KEY'], self.MASTER_REG_REQ_PKT)
        self.transport.write(reg_packet, (self._config['MASTER']['IP'], self._config['MASTER']['PORT']))
        print ("->> Sending Registration to Master:\t", self._config['MASTER']['IP'],":", self._config['MASTER']['PORT'],
               "\tFrom:", binascii.b2a_hex(self._config['LOCAL']['RADIO_ID']), "\n")
        #
        self._call = task.LoopingCall(self.masterKeepalive)
        self._loop = self._call.start(6)

    def datagramReceived(self, data, (host, port)):
        dest_ip = self._config['MASTER']['IP']
        dest_port = self._config['MASTER']['PORT']
        #print "received %r from %s:%d" % (binascii.b2a_hex(data), host, port)
        
        _packettype = (data[0:1])
    
        if (_packettype == MASTER_REG_REQ):
            print("<<- Registration Packet Recieved\n")
            
        elif (_packettype == MASTER_REG_REPLY):
            print("<<- Master Registration Reply From:\t", host,":",port)
            master_alive_packet = hashed_packet(self._config['LOCAL']['AUTH_KEY'], self.MASTER_ALIVE_PKT)
            self.transport.write(master_alive_packet, (host, port))
            print("->> Master Keep Alive Sent To:\t", host,":",port, "\n")
            # the only time we need to ask for the peer list is after we've registered to the master
            peer_list_req_packet = hashed_packet(self._config['LOCAL']['AUTH_KEY'], self.PEER_LIST_REQ_PKT)
            self.transport.write(peer_list_req_packet, (host, port))
            print("->> Peer List Reqested from Master:\t", host,":",port, "\n")
            #print binascii.b2a_hex(peer_list_req_packet)
            
        elif (_packettype == PEER_REG_REQUEST):
            print("<<- Peer Registration Request From:\t", host,":",port)
            peer_reg_reply_packet = hashed_packet(self._config['LOCAL']['AUTH_KEY'], self.PEER_REG_REPLY_PKT)
            self.transport.write(peer_reg_reply_packet, (host, port))
            print("->> Peer Registration Reply Sent To:\t", host,":",port,"\n")
            #print host, port
            #print binascii.b2a_hex(peer_reg_reply_packet)
            
        elif (_packettype == PEER_ALIVE_REQ):
            print("<<- Received Peer Keep Alive From:\t", host,":",port)
            peer_alive_req_packet = hashed_packet(self._config['LOCAL']['AUTH_KEY'], self.PEER_ALIVE_REQ_PKT)
            peer_alive_reply_packet = hashed_packet(self._config['LOCAL']['AUTH_KEY'], self.PEER_ALIVE_REPLY_PKT)
            self.transport.write(peer_alive_reply_packet, (host, port))
            print("->> Sent Peer Keep Alive Reply To:\t\t", host,":",port,)
            self.transport.write(peer_alive_req_packet, (host, port))
            print("->> Sent Peer Keep Alive Request To:\t\t", host,":",port, "\n")
            #print binascii.b2a_hex(peer_alive_req_packet)
            
        elif (_packettype == MASTER_ALIVE_REPLY):
            print("<<- Keep Alive Recieved from Master:\t", host,":",port, "\n")
            
        elif (_packettype == PEER_ALIVE_REPLY):
            print("<<- Keep Alive Recieved from Peer:\t", host,":",port, "\n")
            
        elif (_packettype == RDAC_CTL):
            print("<<- RDAC and/or Control Packet From:\t", host,":",port, "\n")
        
        elif (_packettype == PEER_LIST_REPLY):
            print("<<- The Peer List has been Received from Master:\t", host,":",port)
            _num_peers = int(str(int(binascii.b2a_hex(data[5:7]), 16))[1:])
            print('    There are', _num_peers, 'peers in this IPSC Network')
            for i in range(7, (_num_peers*11)+7, 11):
                self._config['PEERS'].append({
                'RADIO_ID': binascii.b2a_hex(data[i:i+4]), 
                'IP':       binascii.b2a_hex(data[i+4:i+8]), 
                'PORT':     binascii.b2a_hex(data[i+8:i+10]), 
                'MODE':     binascii.b2a_hex(data[i+10:i+11])
                })
            print_peer_list(self._config)
            print()
            
        else:
            packet_type = binascii.b2a_hex(_packettype)
            print("<<- Recieved Unprocessed Type", packet_type, "From:\t", host,":",port,"\n")


if __name__ == '__main__':
    for ipsc_network in NETWORK:
        reactor.listenUDP(NETWORK[ipsc_network]['LOCAL']['PORT'], IPSC(NETWORK[ipsc_network]))
    reactor.run()
