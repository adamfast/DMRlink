# Copyright (c) 2013 Cortney T. Buffington, N0MJS n0mjs@me.com
#
# This work is licensed under the Creative Commons Attribution-ShareAlike
# 3.0 Unported License.To view a copy of this license, visit
# http://creativecommons.org/licenses/by-sa/3.0/ or send a letter to
# Creative Commons, 444 Castro Street, Suite 900, Mountain View,
# California, 94041, USA.

# Configuration file for IPSC.py -- each network has several parts, some of this is muted by the script once it runs, thus there are placeholders
NETWORK = {
    'IPSC1': {
        'GROUP_VOICE': [
            {'SRC_GROUP': b'\x00\x00\x01', 'DST_NET': 'IPSC2', 'DST_GROUP': b'\x00\x00\x02'}
        ],
        'LOCAL': {
            'MODE': b'\x6A',        # Decoded values below, use this only for now
            'PEER_OPER': True,      # Not yet in use, must be hand-coded in MODE
            'PEER_MODE': 'DIGITAL', # Not yet in use, must be hand-coded in MODE
            'TS1_LINK': True,       # Not yet in use, must be hand-coded in MODE
            'TS2_LINK': True,       # Not yet in use, must be hand-coded in MODE
            'FLAGS': b'\x00\x00\x00\x14',
            'PORT': 50001,
            'ALIVE_TIMER': 5, # Seconds between keep-alives and registration attempts
            'MAX_MISSED': 5, # Maximum number of keep-alives missed before de-registration
            'RADIO_ID': b'\x00\x00\x00\x0A',
            'AUTH_ENABLED': True,
            'AUTH_KEY': b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01',
            'ENABLED': True,
            # MAKE NO CHANGES BELOW HERE!!!
            'NUM_PEERS': 0,
            'STATUS': {
                'ACTIVE': False
            }
        },
        'MASTER': {
            'IP': '1.2.3.4',
            'PORT': 50000,
            # MAKE NO CHANGES BELOW HERE!!!
            'RADIO_ID': b'\x00\x00\x00\x00',
            'MODE': b'\x00',
            'PEER_OPER': False,
            'PEER_MODE': '',
            'TS1_LINK': False,
            'TS2_LINK': False,
            'FLAGS': b'\x00\x00\x00\x00',
            'STATUS': {
                'CONNECTED': False,
                'PEER-LIST': False,
                'KEEP_ALIVES_SENT': 0,
                'KEEP_ALIVES_MISSED': 0,
                'KEEP_ALIVES_OUTSTANDING': 0
            }
        },
        'PEERS': []
#        each list item contains {
#           'IP': '100.200.1.1',
#           'PORT': 50000,
#           'RADIO_ID': b'\x00\x00\x00\x00',
#           'MODE': b'\x00,
#           'PEER_OPER': False,
#           'PEER_MODE': '',
#           'TS1_LINK': False,
#           'TS2_LINK': False,
#           'FLAGS': b'\x00\x00\x00\x00',
#           'STATUS': {
#               'CONNECTED': False,
#               'KEEP_ALIVES_SENT': 0,
#               'KEEP_ALIVES_MISSED': 0,  
#               'KEEP_ALIVES_OUTSTANDING': 0
#               }
#       }
    }
}
