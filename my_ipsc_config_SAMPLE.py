# Configuration file for IPSC.py -- each network has several parts, some of this is muted by the script once it runs, thus there are placeholders
NETWORK = {
    'IPSC1': {
        'LOCAL': {
            'DESCRIPTION': 'IPSC Network name',
            'MODE': b'\x6A',
            'FLAGS': b'\x00\x00\x00\x14',
            'PORT': 50001,
            'ALIVE_TIMER': 5, # Seconds between keep-alives and registration attempts
            'RADIO_ID': b'\x00\x00\x00\x0A',
            'AUTH_KEY': b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
        },
        'MASTER': {
            'IP': '1.2.3.4',
            'PORT': 50000,
            'STATUS': {
                'RADIO_ID': b'\x00\x00\x00\x00',
                'CONNECTED': 0,
                'KEEP_ALIVES_MISSED': 0,
                'MODE': b'\x00',
                'FLAGS': b'\x00\x00\x00\x00',
            }
        },
        'PEERS': []
#        each list item contains {
#           'IP': '100.200.1.1',
#           'PORT': 50000,
#           'RADIO_ID': b'\x00\x00\x00\xFF',
#           'STATUS': {
#               'CONNECTED': 0,
#               'KEEP_ALIVES_MISSED': 0
#               }
#       }
    }
}