# LINKING STATUS:
#	Byte 1 - BIT FLAGS:
#	      xx.. .... = Peer Operational (01 only known valid value)
#	      ..xx .... = Peer MODE: 00 - No Radio, 01 - Analog, 10 - Digital
#	      .... xx.. = IPSC Slot 1: 10 on, 01 off 
#	      .... ..xx = IPSC Slot 2: 10 on, 01 off
#   MASK VALUES:
PEER_OP_MSK       = 0b11000000
PEER_MODE_MSK     = 0b00110000
IPSC_TS1_MSK      = 0b00001100
IPSC_TS2_MSK      = 0b00000011

#SERVICE FLAGS:

#	Byte 1 - 0x00  	= Unknown
#	Byte 2 - 0x00	= Unknown
#	Byte 3 - BIT FLAGS:
#	      x... .... = CBSK Message
#	      .x.. .... = Repeater Call Monitoring
#	      ..x. .... = 3rd Party "Console" Application
#	      ...x xxxx = Unknown - default to 0
#   MASK VALUES:
CSBK_MSK          = 0b10000000
RPT_MON_MSK       = 0b01000000
CON_APP_MSK       = 0b00100000

#	Byte 4 = BIT FLAGS:
#	      x... .... = XNL Connected (1=true)
#	      .x.. .... = XNL Master Device
#	      ..x. .... = XNL Slave Device
#	      ...x .... = Set if packets are authenticated
#	      .... x... = Set if data calls are supported
#	      .... .x.. = Set if voice calls are supported
#	      .... ..x. = Unknown - default to 0
#	      .... ...x = Set if master
#   MASK VALUES:
XNL_STAT_MSK       = 0b10000000
XNL_MSTR_MSK       = 0b01000000
XNL_SLAVE_MSK      = 0b00100000
PKT_AUTH_MSK       = 0b00010000
DATA_CALL_MSK      = 0b00001000
VOICE_CALL_MSK     = 0b00000100
MSTR_PEER_MSK      = 0b00000001