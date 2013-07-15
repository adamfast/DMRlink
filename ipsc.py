from __future__ import print_function
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from twisted.internet import task
import sys
import argparse
import binascii
import hmac
import hashlib
import socket
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
    _mode = int(binascii.b2a_hex(_mode), 16)
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
 
def mode_decode(_mode):
    _mode = int(binascii.b2a_hex(_mode), 16)
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
        address         = dictionary['IP']
        port            = dictionary['PORT']
        radio_id        = int(binascii.b2a_hex(dictionary['RADIO_ID']), 16)        
        mode            = dictionary['RAW_MODE']
        int_connected   = dictionary['STATUS']['CONNECTED']
        int_missed      = dictionary['STATUS']['KEEP_ALIVES_MISSED']

        logger.info('\tIP Address: %s:%s', address, port)
        logger.info('\tRADIO ID:   %s ', radio_id)
        logger.info("\tIPSC Mode:")
        print_mode_decode(mode)
        logger.info('\tConnection Status: %s', int_connected)
        logger.info('\tKeepAlives Missed: %s', int_missed)
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
            self.PEER_REG_REQ_PKT     = (PEER_REG_REQ + self._config['LOCAL']['RADIO_ID'] + IPSC_VER)
            self.PEER_REG_REPLY_PKT   = (PEER_REG_REPLY + self._config['LOCAL']['RADIO_ID'] + IPSC_VER)
            self.PEER_ALIVE_REQ_PKT   = (PEER_ALIVE_REQ + self._config['LOCAL']['RADIO_ID'] + self.TS_FLAGS)
            self.PEER_ALIVE_REPLY_PKT = (PEER_ALIVE_REPLY + self._config['LOCAL']['RADIO_ID'] + self.TS_FLAGS)      
        else:
            logger.error("Unexpected arguments found.")
            

    def timed_loop(self):
        _master_connected = self._config['MASTER']['STATUS']['CONNECTED']
        _master_alives_missed = self._config['MASTER']['STATUS']['KEEP_ALIVES_MISSED']
        
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

        else:
            logger.error("->> Master in UNKOWN STATE:%s:%s", self._config['MASTER']['IP'], self._config['MASTER']['PORT'])            

        for peer in (self._config['PEERS']):
            if (peer['RADIO_ID'] == binascii.b2a_hex(self._config['LOCAL']['RADIO_ID'])):
                continue
            if peer['STATUS']['CONNECTED'] == 0:
                peer_reg_packet = hashed_packet(self._config['LOCAL']['AUTH_KEY'], self.PEER_REG_REQ_PKT)
                self.transport.write(peer_reg_packet, (peer['IP'], peer['PORT']))
                logger.info('->> Peer Registration Request To:%s:%s From:%s', peer['IP'], peer['PORT'], binascii.b2a_hex(self._config['LOCAL']['RADIO_ID']))
            elif peer['STATUS']['CONNECTED'] == 1:
                peer_alive_req_packet = hashed_packet(self._config['LOCAL']['AUTH_KEY'], self.PEER_ALIVE_REQ_PKT)
                self.transport.write(peer_reg_packet, (peer['IP'], peer['PORT']))
                logger.info('->> Peer Keep-Alive Request To:%s:%s From:%s', peer['IP'], peer['PORT'], binascii.b2a_hex(self._config['LOCAL']['RADIO_ID']))


    def startProtocol(self):
        #logger.debug("*** config: %s", self._config)
        #logger.info("")
      
        self._call = task.LoopingCall(self.timed_loop)
        self._loop = self._call.start(self._config['LOCAL']['ALIVE_TIMER'])

    def peer_list_received(self, _data, (_host, _port)):
        logger.info("<<- The Peer List has been Received from Master:%s:%s Setting Condition 2", _host, _port)
        _num_peers = int(str(int(binascii.b2a_hex(_data[5:7]), 16))[1:])
        self._config['LOCAL']['NUM_PEERS'] = _num_peers
        self._config['MASTER']['STATUS']['CONNECTED'] = 2
        logger.info('    There are %s peers in this IPSC Network', _num_peers)
        del self._config['PEERS'][:]
        for i in range(7, (_num_peers*11)+7, 11):
            hex_address = (_data[i+4:i+8])
            self._config['PEERS'].append({
                'RADIO_ID': _data[i:i+4], 
                'IP':       socket.inet_ntoa(hex_address), 
                'PORT':     int(binascii.b2a_hex(_data[i+8:i+10]), 16), 
                'RAW_MODE': _data[i+10:i+11],
                'MODE':     mode_decode(_data[i+10:i+11]),
                'STATUS':   {'CONNECTED': 0, 'KEEP_ALIVES_MISSED': 0}
            })
        print_peer_list(self._config)
    
    def datagramReceived(self, data, (host, port)):
        dest_ip = self._config['MASTER']['IP']
        dest_port = self._config['MASTER']['PORT']
        #logger.info("received %r from %s:%d", binascii.b2a_hex(data), host, port)

        _packettype = data[0:1]
        _peerid     = data[1:5]

        if (_packettype == PEER_ALIVE_REQ):
            logger.info("<<- Peer Keep-alive Request From Peer ID %s at:%s:%s", int(binascii.b2a_hex(_peerid), 16), host, port)
            peer_alive_req_packet = hashed_packet(self._config['LOCAL']['AUTH_KEY'], self.PEER_ALIVE_REQ_PKT)
            peer_alive_reply_packet = hashed_packet(self._config['LOCAL']['AUTH_KEY'], self.PEER_ALIVE_REPLY_PKT)
            self.transport.write(peer_alive_reply_packet, (host, port))
            logger.info("->> Peer Keep-alive Reply sent To:%s:%s", host, port)
            self.transport.write(peer_alive_req_packet, (host, port))
            logger.info("->> Peer Keep-alive Request sent To:%s:%s", host, port)

        elif (_packettype == MASTER_ALIVE_REPLY):
            logger.info("<<- Master Keep-alive Reply  From:%s:%s", host, port)

        elif (_packettype == PEER_ALIVE_REPLY):
            logger.info("<<- Peer Keep-alive Reply From:%s:%s", host, port)

        elif (_packettype == MASTER_REG_REQ):
            logger.info("<<- Registration Packet Recieved")

        elif (_packettype == MASTER_REG_REPLY):
            self._config['MASTER']['STATUS']['CONNECTED'] = 1
            logger.info("<<- Master Registration Reply From:%s:%s Setting Condition %s", host, port,self._config['MASTER']['STATUS']['CONNECTED'])

        elif (_packettype == PEER_REG_REQ):
            logger.info("<<- Peer Registration Request From Peer ID %s at:%s:%s", int(binascii.b2a_hex(_peerid), 16), host, port)
            peer_reg_reply_packet = hashed_packet(self._config['LOCAL']['AUTH_KEY'], self.PEER_REG_REPLY_PKT)
            self.transport.write(peer_reg_reply_packet, (host, port))
            logger.info("->> Peer Registration Reply Sent To:%s:%s", host, port)

        elif (_packettype == PEER_REG_REPLY):
            logger.info('<<- Peer Registration Reply From: %s', int(binascii.b2a_hex(_peerid), 16))
            

        elif (_packettype == XCMP_XNL):
            logger.warning("<<- XCMP_XNL From:%s:%s, but we did not indicate XCMP capable!", host, port)

        elif (_packettype == PEER_LIST_REPLY):
            self.peer_list_received(data, (host, port))
            
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