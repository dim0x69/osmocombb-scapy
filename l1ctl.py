#!/usr/bin/python2.7
# L1CTL headers and packets

from scapy.all import *


#msg_type
_L1CTL_NONE = 0
L1CTL_FBSB_REQ = 1
L1CTL_FBSB_CONF = 2
L1CTL_DATA_IND = 3
L1CTL_RACH_REQ = 4
L1CTL_DM_EST_REQ = 5
L1CTL_DATA_REQ = 6
L1CTL_RESET_IND = 7
L1CTL_PM_REQ = 8		# power measurement
L1CTL_PM_CONF = 9		#  power measurement
L1CTL_ECHO_REQ = 10
L1CTL_ECHO_CONF = 11
L1CTL_RACH_CONF = 12
L1CTL_RESET_REQ = 13
L1CTL_RESET_CONF = 14
L1CTL_DATA_CONF = 15
L1CTL_CCCH_MODE_REQ = 16
L1CTL_CCCH_MODE_CONF = 17
L1CTL_DM_REL_REQ = 18
L1CTL_PARAM_REQ = 19
L1CTL_DM_FREQ_REQ = 20
L1CTL_CRYPTO_REQ = 21
L1CTL_SIM_REQ = 22
L1CTL_SIM_CONF = 23
L1CTL_TCH_MODE_REQ = 24
L1CTL_TCH_MODE_CONF = 25
L1CTL_NEIGH_PM_REQ = 26
L1CTL_NEIGH_PM_IND = 27
L1CTL_TRAFFIC_REQ = 28
L1CTL_TRAFFIC_CONF = 29
L1CTL_TRAFFIC_IND = 30

# chan_nr
RSL_CHAN_NR_MASK = 0xf8
RSL_CHAN_Bm_ACCHs = 0x08
RSL_CHAN_Lm_ACCH = 0x10
RSL_CHAN_SDCCH4_ACCH = 0x20
RSL_CHAN_SDCCH8_ACCH = 0x40
RSL_CHAN_BCCH = 0x80
RSL_CHAN_RACH = 0x88
RSL_CHAN_PCH_AGCH = 0x90

# ccch_mode
CCCH_MODE_NONE = 0				# only bcch
CCCH_MODE_NON_COMBINED = 1		# ccch, bcch,...
CCCH_MODE_COMBINED = 2			# ccch, bcch AND SDCCH on TS0 (?)

 

'''
{0xf8:"RSL_CHAN_NR_MASK",
0x08:"RSL_CHAN_Bm_ACCHs",
0x10:"RSL_CHAN_Lm_ACCHs",
0x20:"RSL_CHAN_SDCCH4_ACCH",
0x40:"RSL_CHAN_SDCCH8_ACCH",
0x80:"RSL_CHAN_BCCH",
0x88:"RSL_CHAN_RACH",
0x90:"RSL_CHAN_PCH_AGCH"}

Downlink

'''
class l1ctl_info_dl(Packet):
	fields_desc = [
		ByteEnumField("chan_nr",8,{0xf8:"RSL_CHAN_NR_MASK",
												0x08:"RSL_CHAN_Bm_ACCHs",
												0x10:"RSL_CHAN_Lm_ACCHs",
												0x20:"RSL_CHAN_SDCCH4_ACCH",
												0x40:"RSL_CHAN_SDCCH8_ACCH",
												0x80:"RSL_CHAN_BCCH",
												0x88:"RSL_CHAN_RACH",
												0x90:"RSL_CHAN_PCH_AGCH"}),
		ByteField("link_id",0),
		ShortField("band_arfcn",0),
		IntField("frame_nr",0),
		ByteField("rx_level",0),
		ByteField("snr",0),
		ByteField("num_biterr",0),
		ByteField("fire_crc",0),
	]

''' 
Uplink
'''
class l1ctl_info_ul(Packet):
	fields_desc = [
		ByteField("chan_nr",0),
		ByteField("link_id",0),
		ByteField("padding",0),
		ByteField("padding",0),
	]

class gsm48_system_information_type_header(Packet):
		name = "system information type header"
		fields_desc = [
						ByteField("l2_plen",0),
						BitField("rr_protocol_discriminator",0,4),
						BitField("skip_indicator",0,4),
						ByteField("system_information",0)
						]

class gsm48_paging1(Packet):
		name = "paging request type 1"
		fields_desc = [
						BitField("pag_mode",0,2),
						BitField("spare",0,2),
						BitField("cneed1",0,2),
						BitField("cneed2",0,2),
						ByteField("miPartLength",0),
						StrLenField("mi", None, length_from= lambda pkt:  pkt.miPartLength),
						ByteField("element id",0),
						ByteField("miPartLength2",0),
						StrLenField("mi2", None, length_from= lambda pkt: pkt.miPartLength2)
		]
class l1ctl_hdr(Packet):
	name = "l1ctl_hdr"
	fields_desc = [
		ShortField("length",None),
		ByteField("msg_type",13),
		ByteField("flags",0),
		ByteField("padding",0),
		ByteField("padding",0),
	]

	def post_build(self,p,pay):
		if self.length is None:
			length =  len(pay) + len(p) - 2 #-2 for SortField("length")
			p = struct.pack("!H",length) + p[2:] #add 2 byte long length
		return p + pay

	# remove GSM-padding (0x2b)
	def pre_dissect(self,s):
		i = 0
		for a in reversed(s):
			if ord(a) == 0x2b:
				i += 1
		t = s[0:len(s)-i]
		return t
		

class l1ctl_fbsb_req(Packet):
	name = "l1ctl_fbsb_req"
	fields_desc = [
		ShortField("band_arfcn",44),
		ShortField("timeout",100),
		ShortField("freq_err_thresh1",11000-1000),
		ShortField("freq_err_thresh2",1000-200),
		ByteField("num_freqerr_avg",3),
		ByteField("flags",7),
		ByteField("sync_info_idx",0),
		ByteField("ccch_mode",1)
	]
	
class l1ctl_fbsb_conf(Packet):
		name = "l1ctl_fbsb_conf"
		fields_desc = [
						ShortField("initial_freq_err",0),
						ByteField("result",0),
						ByteField("bsic",0)
						]

class l1ctl_rach_req(Packet): 
	name = "l1ctl_rach_req"
	fields_desc = [
		ByteEnumField("ra",3,{(random.getrandbits(8) & 0x1f) |0xa0:"emergency",#check GSM 04.08 or osmocombb gsm48_rr.c
					  (random.getrandbits(8) & 0x0f) |0x10:"SDCCHwNECI", 
					  (random.getrandbits(8) & 0x1f) |0xe0:"SDCCHwoNECI"}),
		ByteField("combined",0),
		ShortField("offset",0)
		]



class l1ctl_reset(Packet):
	name = "l1ctl_reset"
	fields_desc = [
		ByteEnumField("type",1,{0:"L1CTL_RES_T_BOOT",
								1:"L1CTL_RES_T_FULL",
								2:"L1CTL_RES_T_SCHED"}),
		ByteField("padding",0),
		ByteField("padding",0),
		ByteField("padding",0)

	]

class l1ctl_pm_req(Packet):
	name = "l1ctl_pm_req"
	fields_desc = [
		ByteField("type",1),
		ByteField("padding",0),
		ByteField("padding",0),
		ByteField("padding",0),
		ShortField("from",0),
		ShortField("to",0)
					]

class l1ctl_pm_list(Packet):
		name ="l1ctl_pm_list"
		fields_desc = [
					ByteField("band_arfcn",5),
					ByteField("pm1",0),
					ByteField("pm1",0)
					]

class l1ctl_pm_conf(Packet):
	name = "l1ctl_pm_conf"
	fields_desc = [
					PacketListField("pmlist", [], l1ctl_pm_list, count_from = lambda pkt: pkt.underlayer.length / 4 - 1)
			]

# bind the layers for guess_payload (dissecting with scapy)
bind_layers(l1ctl_hdr,l1ctl_fbsb_conf,msg_type=L1CTL_FBSB_CONF)
bind_layers(l1ctl_hdr,l1ctl_info_dl,msg_type=L1CTL_DATA_IND)
bind_layers(l1ctl_info_dl,gsm48_system_information_type_header, chan_nr=RSL_CHAN_PCH_AGCH)
bind_layers(gsm48_system_information_type_header, gsm48_paging1, system_information = 0x21) #paging req type 1
bind_layers(l1ctl_hdr,l1ctl_pm_conf,msg_type=L1CTL_PM_CONF) #power measurement data
