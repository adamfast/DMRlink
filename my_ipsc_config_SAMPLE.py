# Configuration file for IPSC.py -- each network has several parts, some of this is muted by the script once it runs, thus there are placeholders
NETWORK = {
    'IPSC1': {
        'LOCAL': {
            'MODE': b'\x6A', # Decoded values below
            'PEER_OPER': True,
            'PEER_MODE': 'DIGITAL',
            'TS1_LINK': True,
            'TS2_LINK': True,
            'FLAGS': b'\x00\x00\x00\x14',
            'PORT': 50001,
            'NUM_PEERS': 0,
            'ALIVE_TIMER': 5, # Seconds between keep-alives and registration attempts
            'MAX_MISSED': 5, # Maximum number of keep-alives missed before de-registration
            'RADIO_ID': b'\x00\x00\x00\x0A',
            'AUTH_KEY': b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01',
            'ENABLED': True,
            'STATUS': {
                'ACTIVE': False
            }
        },
        'MASTER': {
            'IP': '1.2.3.4',
            'PORT': 50000,
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
