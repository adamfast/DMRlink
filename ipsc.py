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
#
try:
    from ipsc_logger import logger
except ImportError:
    sys.exit('System logger configuraiton not found or invalid')

# Import configuration and informational data structures
#
try:
    from my_ipsc_config import NETWORK
except ImportError:
    sys.exit('Configuration file not found, or not valid formatting')

# Import IPSC message types and version information
#
try:
    from ipsc_message_types import *
except ImportError:
    sys.exit('IPSC message types file not found or invalid')

# Import IPSC flag mask values
#
try:
    from ipsc_mask import *
except ImportError:
    sys.exit('IPSC mask values file not found or invalid')
   


#************************************************
#     GLOBALLY SCOPED FUNCTIONS
#************************************************


# Take a packet to be SENT, calcualte auth hash and return the whole thing
#
def hashed_packet(_key, _data):
    hash = binascii.unhexlify((hmac.new(_key,_data,hashlib.sha1)).hexdigest()[:20])
    return (_data + hash)
    
    
# Take a RECEIVED packet, calculate the auth hash and verify authenticity
#
def validate_auth(_key, _data):
    return

# Decide the Mode bit flags and print them - later, use this for more
# than just informational purposes, for now, it's FYI/Debug info.
#
def print_mode_decode(_mode):
    _log = logger.info
    _mode = int(binascii.b2a_hex(_mode), 16)
    link_op   = _mode & PEER_OP_MSK
    link_mode = _mode & PEER_MODE_MSK
    ts1       = _mode & IPSC_TS1_MSK
    ts2       = _mode & IPSC_TS2_MSK
    
    if link_op == 0b01000000:
        _log('\t\tPeer Operational')
    elif link_op == 0b00000000:
        _log('\t\tPeer Not Operational')
    else:
        _log('\t\tPeer Mode Invalid')
        
    if link_mode == 0b00000000:
        _log('\t\tNo RF Interface')
    elif link_mode == 0b00010000:
        _log('\t\tRadio in Analog Mode')
    elif link_mode == 0b00100000:
        _log('\t\tRadio in Digital Mode')
    else:
        _log('\t\tRadio Mode Invalid')
        
    if ts1 == 0b00001000:
        _log('\t\tIPSC Enabled on TS1')
    
    if ts2 == 0b00000010:
        _log('\t\tIPSC Enabled on TS2')


# Gratuituous print-out of the peer list.. Pretty much debug stuff.
#
def print_peer_list(_network_name):
    _log = logger.info
    _log('\t Peer List for: %s', _network_name)
    for dictionary in NETWORK[_network_name]['PEERS']:    
        _log('\t  IP Address: %s:%s', dictionary['IP'], dictionary['PORT'])
        _log('\t  RADIO ID:   %s ', int(binascii.b2a_hex(dictionary['RADIO_ID']), 16))
        _log('\t  IPSC Mode:')
        print_mode_decode(dictionary['MODE'])
        _log('\t  Connection Status:      %s', dictionary['STATUS']['CONNECTED'])
        _log('\t  KeepAlives Sent:        %s', dictionary['STATUS']['KEEP_ALIVES_SENT'])
        _log('\t  KeepAlives Outstanding: %s', dictionary['STATUS']['KEEP_ALIVES_OUTSTANDING'])
        _log('\t  KeepAlives Missed:      %s', dictionary['STATUS']['KEEP_ALIVES_MISSED'])
        _log('')
        


#************************************************
#********                             ***********
#********    IPSC Network 'Engine'    ***********
#********                             ***********
#************************************************

#************************************************
#     INITIAL SETUP of IPSC INSTANCE
#************************************************

class IPSC(DatagramProtocol):
    
    # Modify the initializer to set up our environment and build the packets
    # we need to maitain connections
    #
    def __init__(self, *args, **kwargs):
        if len(args) == 1:
            # Housekeeping: create references to the configuration and status data for this IPSC instance.
            # Some configuration objects that are used frequently and have lengthy names are shortened
            # such as (self._master_sock) expands to (self._config['MASTER']['IP'], self._config['MASTER']['PORT'])
            #
            self._network = args[0]
            self._config = NETWORK[self._network]
            #
            self._local = self._config['LOCAL']
            self._local_stat = self._local['STATUS']
            self._local_id = self._local['RADIO_ID']
            #
            self._master = self._config['MASTER']
            self._master_stat = self._master['STATUS']
            self._master_sock = self._master['IP'], self._master['PORT']
            #
            self._peers = self._config['PEERS']
            
            args = ()
            
            # Packet 'constructors' - builds the necessary control packets for this IPSC instance
            #
            self.TS_FLAGS             = (self._local['MODE'] + self._local['FLAGS'])
            self.MASTER_REG_REQ_PKT   = (MASTER_REG_REQ + self._local_id + self.TS_FLAGS + IPSC_VER)
            self.MASTER_ALIVE_PKT     = (MASTER_ALIVE_REQ + self._local_id + self.TS_FLAGS + IPSC_VER)
            self.PEER_LIST_REQ_PKT    = (PEER_LIST_REQ + self._local_id)
            self.PEER_REG_REQ_PKT     = (PEER_REG_REQ + self._local_id + IPSC_VER)
            self.PEER_REG_REPLY_PKT   = (PEER_REG_REPLY + self._local_id + IPSC_VER)
            self.PEER_ALIVE_REQ_PKT   = (PEER_ALIVE_REQ + self._local_id + self.TS_FLAGS)
            self.PEER_ALIVE_REPLY_PKT = (PEER_ALIVE_REPLY + self._local_id + self.TS_FLAGS)
            self._peer_list_new = False      
        else:
            # If we didn't get called correctly, log it!
            #
            logger.error('(%s) Unexpected arguments found.', self._network)
            
    # This is called by REACTOR when it starts, We use it to set up the timed
    # loop for each instance of the IPSC engine
    #       
    def startProtocol(self):
        # Timed loop for IPSC connection establishment and maintenance
        # Others could be added later for things like updating a Web
        # page, etc....
        #
        self._call = task.LoopingCall(self.timed_loop)
        self._loop = self._call.start(self._local['ALIVE_TIMER'])


#************************************************
#     FUNCTIONS FOR IPSC Network Engine
#************************************************

    # Process a received peer list:
    #   Flag we have a list
    #   Flag the list is new (needed elsewhere)
    #   Populate the peer information from the list
    #
    def peer_list_received(self, _data, (_host, _port)):
        self._master_stat['PEER-LIST'] = True
        logger.info('<<- (%s) The Peer List has been Received from Master:%s:%s ', self._network, _host, _port)
        _num_peers = int(str(int(binascii.b2a_hex(_data[5:7]), 16))[1:])
        self._local['NUM_PEERS'] = _num_peers
        logger.info('    There are %s peers in this IPSC Network', _num_peers)
        del self._peers[:]
        for i in range(7, (_num_peers*11)+7, 11):
            hex_address = (_data[i+4:i+8])
            self._peers.append({
                'RADIO_ID': _data[i:i+4], 
                'IP':       socket.inet_ntoa(hex_address), 
                'PORT':     int(binascii.b2a_hex(_data[i+8:i+10]), 16), 
                'MODE':     _data[i+10:i+11],
                'STATUS':   {'CONNECTED': False, 'KEEP_ALIVES_SENT': 0, 'KEEP_ALIVES_MISSED': 0, 'KEEP_ALIVES_OUTSTANDING': 0}
            })



#************************************************
#     TIMED LOOP - MY CONNECTION MAINTENANCE
#************************************************

    def timed_loop(self):
        logger.debug('timed loop started') # temporary debugging to make sure this part runs
        
        print_peer_list(self._network)
        
        _master_connected = self._master_stat['CONNECTED']
        _peer_list_rx = self._master_stat['PEER-LIST']

        if (_master_connected == False):
            reg_packet = hashed_packet(self._local['AUTH_KEY'], self.MASTER_REG_REQ_PKT)
            self.transport.write(reg_packet, (self._master_sock))
            logger.info('->> (%s) Master Registration Request To:%s From:%s', self._network, self._master_sock, binascii.b2a_hex(self._local_id))
        
        elif (_master_connected == True):
            master_alive_packet = hashed_packet(self._local['AUTH_KEY'], self.MASTER_ALIVE_PKT)
            self.transport.write(master_alive_packet, (self._master_sock))
            logger.debug('->> (%s) Master Keep-alive %s Sent To:%s', self._network, self._master_stat['KEEP_ALIVES_SENT'], self._master_sock)
            self._master_stat['KEEP_ALIVES_SENT'] += 1
            
            if (self._master_stat['KEEP_ALIVES_OUTSTANDING']) > 0:
                self._master_stat['KEEP_ALIVES_MISSED'] += 1
            
            if self._master_stat['KEEP_ALIVES_OUTSTANDING'] >= self._local['MAX_MISSED']:
                self._master_stat['CONNECTED'] = False
                logger.error('Maximum Master Keep-Alives Missed -- De-registering the Master')
            
        else:
            logger.error('->> (%s) Master in UNKOWN STATE:%s:%s', self._network, self._master_sock)
                
        if  ((_master_connected == True) and (_peer_list_rx == False)):     
            peer_list_req_packet = hashed_packet(self._local['AUTH_KEY'], self.PEER_LIST_REQ_PKT)
            self.transport.write(peer_list_req_packet, (self._master_sock))
            logger.debug('->> (%s) List Reqested from Master:%s', self._network, self._master_sock)

# Logic problems in the next if.... bad ones. Fix them.
        if (_peer_list_rx == True):
            for peer in (self._peers):
                if (peer['RADIO_ID'] == self._local_id): # We are in the peer-list, but don't need to talk to ourselves
                    continue
                if peer['STATUS']['CONNECTED'] == False:
                    peer_reg_packet = hashed_packet(self._local['AUTH_KEY'], self.PEER_REG_REQ_PKT)
                    self.transport.write(peer_reg_packet, (peer['IP'], peer['PORT']))
                    logger.debug('->> (%s) Peer Registration Request To:%s:%s From:%s', self._network, peer['IP'], peer['PORT'], binascii.b2a_hex(self._local_id))
                elif peer['STATUS']['CONNECTED'] == True:
                    peer_alive_req_packet = hashed_packet(self._local['AUTH_KEY'], self.PEER_ALIVE_REQ_PKT)
                    self.transport.write(peer_alive_req_packet, (peer['IP'], peer['PORT']))
                    logger.debug('->> (%s) Peer Keep-Alive Request To:%s:%s From:%s', self._network, peer['IP'], peer['PORT'], binascii.b2a_hex(self._local_id))

                    peer['STATUS']['KEEP_ALIVES_SENT'] += 1
            
                    if peer['STATUS']['KEEP_ALIVES_OUTSTANDING'] > 0:
                        peer['STATUS']['KEEP_ALIVES_MISSED'] += 1
            
                    if peer['STATUS']['KEEP_ALIVES_OUTSTANDING'] >= self._local['MAX_MISSED']:
                        peer['STATUS']['CONNECTED'] = False
                        logger.error('Maximum Peer Keep-Alives Missed -- De-registering the Peer')
        
        logger.debug('(%s) timed loop finished', self._network) # temporary debugging to make sure this part runs
    
    
    
#************************************************
#     RECEIVED DATAGRAM - ACT IMMEDIATELY!!!
#************************************************

    # Work in progress -- at the very least, notify we have the packet. Ultimately
    # call a function or process immediately if only a few actions
    #
    def datagramReceived(self, data, (host, port)):
        logger.debug('datagram received') # temporary debugging to make sure this part runs
        #logger.debug('received %r from %s:%d', binascii.b2a_hex(data), host, port)

        _packettype = data[0:1]
        _peerid     = data[1:5]
        _dec_peerid = int(binascii.b2a_hex(_peerid), 16)

        if (_packettype == PEER_ALIVE_REQ):
            logger.debug('<<- (%s) Peer Keep-alive Request From Peer ID %s at:%s:%s', self._network, _dec_peerid, host, port)
            peer_alive_reply_packet = hashed_packet(self._local['AUTH_KEY'], self.PEER_ALIVE_REPLY_PKT)
            self.transport.write(peer_alive_reply_packet, (host, port))
            logger.debug('->> (%s) Peer Keep-alive Reply sent To:%s:%s', self._network, host, port)

        elif (_packettype == MASTER_ALIVE_REPLY):
            logger.debug('<<- (%s) Master Keep-alive Reply From: %s \t@ IP: %s:%s', self._network, _dec_peerid, host, port)
            #### increment keep-alive outstanding here

        elif (_packettype == PEER_ALIVE_REPLY):
            logger.debug('<<- (%s) Peer Keep-alive Reply From:   %s \t@ IP: %s:%s', self._network, _dec_peerid, host, port)
            #### increment keep-alive outstanding here
            
        elif (_packettype == MASTER_REG_REQ):
            logger.info('<<- (%s) Master Registration Packet Recieved', self._network)

        elif (_packettype == MASTER_REG_REPLY):
            self._master_stat['CONNECTED'] = True
            self._master_stat['KEEP_ALIVES_OUTSTANDING'] = 0
            logger.info('<<- (%s) Master Registration Reply From:%s:%s ', self._network, host, port)

        elif (_packettype == PEER_REG_REQ):
            logger.debug('<<- (%s) Peer Registration Request From Peer ID %s at:%s:%s', self._network, _dec_peerid, host, port)
            peer_reg_reply_packet = hashed_packet(self._local['AUTH_KEY'], self.PEER_REG_REPLY_PKT)
            self.transport.write(peer_reg_reply_packet, (host, port))
            logger.debug('->> (%s) Peer Registration Reply Sent To:%s:%s', self._network, host, port)

        elif (_packettype == PEER_REG_REPLY):
            logger.debug('<<- (%s) Peer Registration Reply From: %s \t@ IP: %s:%s', self._network, _dec_peerid, host, port)
            for peer in self._config['PEERS']:
                if peer['RADIO_ID'] == _peerid:
                    peer['STATUS']['CONNECTED'] = True

        elif (_packettype == XCMP_XNL):
            logger.debug('<<- (%s) XCMP_XNL From:%s:%s, but we did not indicate XCMP capable!', self._network, host, port)

        elif (_packettype == PEER_LIST_REPLY):
            self.peer_list_received(data, (host, port))
            
        elif (_packettype == GROUP_VOICE):
            logger.debug('<<- (%s) Group Voice Packet From:%s:%s', self._network, host, port)
            
        elif (_packettype == PVT_VOICE):
            logger.debug('<<- (%s) Voice Packet From:%s:%s', self._network, host, port)
            
        elif (_packettype == GROUP_DATA):
            logger.debug('<<- (%s) Group Data Packet From:%s:%s', self._network, host, port)
            
        elif (_packettype == PVT_DATA):
            logger.debug('<<- (%s) Private Data Packet From From:%s:%s', self._network, host, port)
            
        elif (_packettype == RPT_WAKE_UP):
            logger.debug('<<- (%s) Repeater Wake-Up Packet From:%s:%s', self._network, host, port)
            
        elif (_packettype == DE_REG_REQ):
            logger.debug('<<- (%s) Peer De-Registration Request From:%s:%s', self._network, host, port)
            
        elif (_packettype == DE_REG_REPLY):
            logger.debug('<<- (%s) Peer De-Registration Reply From:%s:%s', self._network, host, port)
            
        elif (_packettype in (CALL_CTL_1, CALL_CTL_2, CALL_CTL_3)):
            logger.debug('<<- (%s) Call Control Packet From:%s:%s', self._network, host, port)
            
        else:
            packet_type = binascii.b2a_hex(_packettype)
            logger.error('<<- (%s) Received Unprocessed Type %s From:%s:%s', self._network, packet_type, host, port)



#************************************************
#      MAIN PROGRAM LOOP STARTS HERE
#************************************************

if __name__ == '__main__':
    for ipsc_network in NETWORK:
        if (NETWORK[ipsc_network]['LOCAL']['ENABLED']):
            reactor.listenUDP(NETWORK[ipsc_network]['LOCAL']['PORT'], IPSC(ipsc_network))
    reactor.run()