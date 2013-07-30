# Known IPSC Message Types
CALL_CTL_1            = b'\x61' #  |
CALL_CTL_2            = b'\x62' #  | Exact meaning unknown
CALL_CTL_3            = b'\x63' #  |
XCMP_XNL              = b'\x70' # XCMP/XNL control message
GROUP_VOICE           = b'\x80'
PVT_VOICE             = b'\x81'
GROUP_DATA            = b'\x83'
PVT_DATA              = b'\x84'
RPT_WAKE_UP           = b'\x85' # Similar to OTA DMR "wake up"
MASTER_REG_REQ        = b'\x90' # FROM peer TO master
MASTER_REG_REPLY      = b'\x91' # FROM master TO peer
PEER_LIST_REQ         = b'\x92'
PEER_LIST_REPLY       = b'\x93'
PEER_REG_REQ          = b'\x94' # Peer registration request
PEER_REG_REPLY        = b'\x95' # Peer registration reply
MASTER_ALIVE_REQ      = b'\x96' # FROM peer TO master
MASTER_ALIVE_REPLY    = b'\x97' # FROM master TO peer
PEER_ALIVE_REQ        = b'\x98' # Peer keep alive request
PEER_ALIVE_REPLY      = b'\x99' # Peer keep alive reply
DE_REG_REQ            = b'\x9A' # Request de-registration from system
DE_REG_REPLY          = b'\x9B' # De-registration reply

# IPSC Version Information
IPSC_VER_14           = b'\x00'
IPSC_VER_15           = b'\x00'
IPSC_VER_15A          = b'\x00'
IPSC_VER_16           = b'\x01'
IPSC_VER_17           = b'\x02'
IPSC_VER_18           = b'\x02'
IPSC_VER_19           = b'\x03'
IPSC_VER_22           = b'\x04'

# Link Type Values - assumed that cap+, etc. are different, this is all I can confirm
LINK_TYPE_IPSC        = b'\x04'

# IPSC Version and Link Type are Used for a 4-byte version field in registration packets
IPSC_VER              = LINK_TYPE_IPSC + IPSC_VER_19 + LINK_TYPE_IPSC + IPSC_VER_17

# Conditions for accepting certain types of messages... the cornerstone of a secure IPSC system :)
REQ_VALID_PEER = [
    PEER_REG_REQ,
    PEER_REG_REPLY
]

REQ_VALID_MASTER = [
    MASTER_REG_REQ,
    MASTER_REG_REPLY
]

REQ_MASTER_CONNECTED = [
    CALL_CTL_1,
    CALL_CTL_2,
    CALL_CTL_3,
    XCMP_XNL,
    GROUP_VOICE,
    PVT_VOICE,
    GROUP_DATA,
    GROUP_VOICE,
    PVT_DATA,
    RPT_WAKE_UP,
    MASTER_ALIVE_REQ,
    MASTER_ALIVE_REPLY,
    DE_REG_REQ,
    DE_REG_REPLY 
]

REQ_PEER_CONNECTED = [
    PEER_ALIVE_REQ,
    PEER_ALIVE_REPLY
]

REQ_VALID_MASTER_OR_PEER = [
    REQ_VALID_PEER, REQ_VALID_MASTER
]