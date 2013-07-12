from __future__ import print_function
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from twisted.internet import task
import sys
import argparse
import binascii
import hmac
import hashlib
#from logging.config import dictConfig
#import logging



#************************************************
#     IMPORTING OTHER FILES - '#include'
#************************************************

# Import system logger configuration
try:
    from ipsc_logger import logger
except ImportError:
    sys.exit('System logger configuraiton not found or invalid')

# Import configuration and informational data structures
try:
    from my_ipsc_config import NETWORK
except ImportError:
    sys.exit('Configuration file not found, or not valid formatting')

# Import IPSC message types and version information
try:
    from ipsc_message_types import *
except ImportError:
    sys.exit('IPSC message types file not found or invalid')

# Import IPSC flag mask values
try:
    from ipsc_mask import *
except ImportError:
    sys.exit('IPSC mask values file not found or invalid')
   


#************************************************
#     GLOBALLY SCOPED FUNCTIONS
#************************************************

def hashed_packet(_key, _data):
    hash = binascii.unhexlify((hmac.new(_key,_data,hashlib.sha1)).hexdigest()[:20])
    return (_data + hash)

def validate_auth(_key, _data):
    return

def print_mode_decode(_mode):
    _mode = int(_mode, 16)
    link_op   = _mode & PEER_OP_MSK
    link_mode = _mode & PEER_MODE_MSK
    ts1       = _mode & IPSC_TS1_MSK
    ts2       = _mode & IPSC_TS2_MSK
    
    if link_op == 0b01000000:
        logger.info('\t\tPeer Operational')
    elif link_op == 0b00000000:
        logger.info('\t\tPeer Not Operational')
    else:
        logger.warning('\t\tPeer Mode Invalid')
        
    if link_mode == 0b00000000:
        logger.info('\t\tNo RF Interface')
    elif link_mode == 0b00010000:
        logger.info('\t\tRadio in Analog Mode')
    elif link_mode == 0b00100000:
        logger.info('\t\tRadio in Digital Mode')
    else:
        logger.warning('\t\tRadio Mode Invalid')
        
    if ts1 == 0b00001000:
        logger.info('\t\tIPSC Enabled on TS1')
    
    if ts2 == 0b00000010:
        logger.info('\t\tIPSC Enabled on TS2')
    
def print_peer_list(_ipsc_network):
    logger.info('\t%s', _ipsc_network['LOCAL']['DESCRIPTION'])
    for dictionary in _ipsc_network['PEERS']:
        hex_address = dictionary['IP']
        hex_port = dictionary['PORT']
        hex_radio_id = dictionary['RADIO_ID']
        hex_mode = dictionary['MODE']

        address = [int(hex_address[0:2], 16), int(hex_address[2:4], 16), int(hex_address[4:6], 16), int(hex_address[6:8], 16)]
        port = int(hex_port, 16)
        radio_id = int(hex_radio_id, 16)

        logger.info('\tIP Address: %s.%s.%s.%s:%s', address[0], address[1], address[2], address[3], port)
        logger.info('\tRADIO ID:   %s ', radio_id)
        logger.info("\tIPSC Mode:")
        print_mode_decode(hex_mode)
        logger.info("")
        

#************************************************
#     IPSC Network Engine
#************************************************

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
            logger.error("Unexpected arguments found.")

    def keepAlive(self):
        _master_connected = self._config['MASTER']['STATUS']['CONNECTED']
#        logger.debug("keepAlive Routine Running in Condition %s", _master_connected)
        
        if (_master_connected == 0):
            reg_packet = hashed_packet(self._config['LOCAL']['AUTH_KEY'], self.MASTER_REG_REQ_PKT)
            self.transport.write(reg_packet, (self._config['MASTER']['IP'], self._config['MASTER']['PORT']))
            logger.info("->> Master Registration Request To:%s:%s From:%s", self._config['MASTER']['IP'], self._config['MASTER']['PORT'], binascii.b2a_hex(self._config['LOCAL']['RADIO_ID']))
        
        elif (_master_connected in (1,2)):
            if (_master_connected == 1):
                peer_list_req_packet = hashed_packet(self._config['LOCAL']['AUTH_KEY'], self.PEER_LIST_REQ_PKT)
                self.transport.write(peer_list_req_packet, (self._config['MASTER']['IP'], self._config['MASTER']['PORT']))
                logger.info("->> List Reqested from Master:%s:%s", self._config['MASTER']['IP'], self._config['MASTER']['PORT'])

            master_alive_packet = hashed_packet(self._config['LOCAL']['AUTH_KEY'], self.MASTER_ALIVE_PKT)
            self.transport.write(master_alive_packet, (self._config['MASTER']['IP'], self._config['MASTER']['PORT']))
            logger.info("->> Master Keep-alive Sent To:%s:%s", self._config['MASTER']['IP'], self._config['MASTER']['PORT'])

        elif (_master_connected == 2):
            master_alive_packet = hashed_packet(self._config['LOCAL']['AUTH_KEY'], self.MASTER_ALIVE_PKT)
            self.transport.write(master_alive_packet, (self._config['MASTER']['IP'], self._config['MASTER']['PORT']))
            logger.info("->> Master Keep-alive Sent To:%s:%s", self._config['MASTER']['IP'], self._config['MASTER']['PORT'])

        else:
            logger.error("->> Master in UNKOWN STATE:%s:%s", self._config['MASTER']['IP'], self._config['MASTER']['PORT'])            

            
#        logger.debug("keepAlive Routine ending at Condition %s", _master_connected)

    def startProtocol(self):
        #logger.debug("*** config: %s", self._config)
        #logger.info("")
      
        self._call = task.LoopingCall(self.keepAlive)
        self._loop = self._call.start(self._config['LOCAL']['ALIVE_TIMER'])

    def datagramReceived(self, data, (host, port)):
        dest_ip = self._config['MASTER']['IP']
        dest_port = self._config['MASTER']['PORT']
        #logger.info("received %r from %s:%d", binascii.b2a_hex(data), host, port)

        _packettype = (data[0:1])
        _peerid = (data[1:5])

        if (_packettype == PEER_ALIVE_REQ):
            logger.info("<<- Peer Keep-alive Request From Peer ID %s at:%s:%s", int(binascii.b2a_hex(_peerid), 16), host, port)
            peer_alive_req_packet = hashed_packet(self._config['LOCAL']['AUTH_KEY'], self.PEER_ALIVE_REQ_PKT)
            peer_alive_reply_packet = hashed_packet(self._config['LOCAL']['AUTH_KEY'], self.PEER_ALIVE_REPLY_PKT)
            self.transport.write(peer_alive_reply_packet, (host, port))
            logger.info("->> Peer Keep-alive Reply sent To:%s:%s", host, port)
            self.transport.write(peer_alive_req_packet, (host, port))
            logger.info("->> Peer Keep-alive Request sent To:%s:%s", host, port)
            #logger.info(binascii.b2a_hex(peer_alive_req_packet))

        elif (_packettype == MASTER_ALIVE_REPLY):
            logger.info("<<- Master Keep-alive Reply  From:%s:%s", host, port)

        elif (_packettype == PEER_ALIVE_REPLY):
            logger.info("<<- Peer Keep-alive Reply From:%s:%s", host, port)

        elif (_packettype == MASTER_REG_REQ):
            logger.info("<<- Registration Packet Recieved")

        elif (_packettype == MASTER_REG_REPLY):
            self._config['MASTER']['STATUS']['CONNECTED'] = 1
            logger.info("<<- Master Registration Reply From:%s:%s Setting Condition %s", host, port,self._config['MASTER']['STATUS']['CONNECTED'])

        elif (_packettype == PEER_REG_REQUEST):
            logger.info("<<- Peer Registration Request From Peer ID %s at:%s:%s", int(binascii.b2a_hex(_peerid), 16), host, port)
            peer_reg_reply_packet = hashed_packet(self._config['LOCAL']['AUTH_KEY'], self.PEER_REG_REPLY_PKT)
            self.transport.write(peer_reg_reply_packet, (host, port))
            logger.info("->> Peer Registration Reply Sent To:%s:%s", host, port)
            #logger.info("%s:%s", host, port)
            #logger.info(binascii.b2a_hex(peer_reg_reply_packet))

        elif (_packettype == XCMP_XNL):
            logger.warning("<<- XCMP_XNL Packet From:%s:%s - We did not indicate XCMP capable!", host, port)

        elif (_packettype == PEER_LIST_REPLY):
            logger.info("<<- The Peer List has been Received from Master:%s:%s Setting Condition 2", host, port)
            self._config['MASTER']['STATUS']['CONNECTED'] = 2
            _num_peers = int(str(int(binascii.b2a_hex(data[5:7]), 16))[1:])
            logger.info('    There are %s peers in this IPSC Network', _num_peers)
            del self._config['PEERS'][:]
            for i in range(7, (_num_peers*11)+7, 11):
                self._config['PEERS'].append({
                'RADIO_ID': binascii.b2a_hex(data[i:i+4]), 
                'IP':       binascii.b2a_hex(data[i+4:i+8]), 
                'PORT':     binascii.b2a_hex(data[i+8:i+10]), 
                'MODE':     binascii.b2a_hex(data[i+10:i+11])
                })
            print_peer_list(self._config)
            logger.info("")
            
        elif (_packettype == GROUP_VOICE):
            logger.info("<<- Group Voice Packet From:%s:%s", host, port)
            
        elif (_packettype == PVT_VOICE):
            logger.info("<<-  Voice Packet From:%s:%s", host, port)
            
        elif (_packettype == GROUP_DATA):
            logger.info("<<- Group Data Packet From:%s:%s", host, port)
            
        elif (_packettype == PVT_DATA):
            logger.info("<<- Private Data Packet From From:%s:%s", host, port)
            
        elif (_packettype == RPT_WAKE_UP):
            logger.info("<<- Repeater Wake-Up Packet From:%s:%s", host, port)
            
        elif (_packettype == DE_REG_REQ):
            logger.info("<<- Peer De-Registration Request From:%s:%s", host, port)
            
        elif (_packettype == DE_REG_REPLY):
            logger.info("<<- Peer De-Registration Reply From:%s:%s", host, port)
            
        elif (_packettype in (CALL_CTL_1, CALL_CTL_2, CALL_CTL_3)):
            logger.info("<<- Call Control Packet From:%s:%s", host, port)
            
        else:
            packet_type = binascii.b2a_hex(_packettype)
            logger.error("<<- Received Unprocessed Type %s From:%s:%s", packet_type, host, port)

#************************************************
#      MAIN PROGRAM LOOP STARTS HERE
#************************************************

if __name__ == '__main__':
    logger.info('SYSTEM STARTING UP')
    for ipsc_network in NETWORK:
        reactor.listenUDP(NETWORK[ipsc_network]['LOCAL']['PORT'], IPSC(NETWORK[ipsc_network]))
    reactor.run()