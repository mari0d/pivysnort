#!/usr/bin/env python

#	pivysnort.py v1.1 by Mario R. De Tore, SLAC National Accelerator Laboratory
#	
#	Useful for generating Snort signature content for known PI passwords and conducting 
#   dictionary attacks against traffic from implants using an unknown password.
#
#   Usage: pivysnort.py [options]
#
#   Options:
#      -h, --help            show this help message and exit
#      -p PASSWORD, --password=PASSWORD
#                            Plaintext Poison Ivy password
#      -k KEY, --key=KEY     A key in plain hex format
#      -a, --all             Print full Snort signature vice just msg, content and
#                            depth (you must edit the SID)
#      -x, --experimental    Include experimental signatures
#      -r PCAP, --read=PCAP  Attempt to crack PI password for supplied PI traffic
#                            in PCAP format. If a password or key argument is
#                            supplied that password or key will be tried. Additional
#                            passwords can be piped in via STDIN
#
#   Dependencies: 
#   camcrypt - https://github.com/knowmalware/camcrypt (please make sure to update 
#   LIBRARY_PATH in this script)
#   dpkt - https://code.google.com/p/dpkt/
#
#   pivysnort now includes the capability to ingest network traffic (libpcap/tcpdump 
#   formats, not pcapng) to attempt recovery of a PI implant password via a dictionary 
#   attack. This works by extracting encrypted portions of the PI handshake or encrypted 
#   heartbeats and then running a dictionary attack in an attempt to guess the password 
#   needed to decrypt the traffic. Candidate passwords can be piped to the script:
#
#   cat passwords.txt | ./pivysnort.py -r ~/evil.pcap 
#   ./john --wordlist=passwords.txt --rules --stdout | ./pivysnort.py -r ~/evil.pcap
#
#	A number of common APT passwords as documented in FireEye's PI report are checked by 
#   default. These can be updated manually via pw_list. Passwords are entered as strings, 
#   keys are entered as integers (the script will do the needed conversions at run-time).
#
#
#   Note that neither a full PI handshake or full duplex traffic are required for this
#   technique to work. 
#
#	The following resources provided much appreciated technical insights on the PI 
#	protocol:
#	https://www.fireeye.com/resources/pdfs/fireeye-poison-ivy-report.pdf
#	https://github.com/MITRECND/chopshop/blob/master/modules/poisonivy_23x.py
#
#	PI utilizes camellia for encryption which has a 16 byte blocksize. Prior to encryption
#	data to be sent over the wire is prepended with a 32 byte header as described in the 
#	above resources:
#
#		struct PI_chunk_header {
#		int command_id;
#		int stream_id;
#		int padded_chunk_size;
#		int chunk_size;
#		int decompressed_chunk_size;
#		long total_stream_size;
#		int padding;
#		}
#
#	One of the unique characteristics of PI is that the implant is a stub loader - most
#	modules are pushed as shellcode to the implant "on demand". Because of this we can
#	reliably predict what the initial 16 bytes of traffic needed for a Snort signature 
#	from the server to the client will be once a module is put in use. This reliance on 
#	shellcode transfer is also reflected in traffic after the initial 256 byte handshake. 
#	Immediately after the handshake the server will push an initial shellcode load 
#	prepended by the byte sequence  "d0150000" which is the shellcode payload length in 
#	NBO. Note that these four bytes are unencrypted unlike the shellcode that follows.
#
#	One caveat to predicting the initial 16 byte header is the use of stream IDs by PI
#	to allow multiple simultaneous network connections. The predicted header primitives, 
#	called prototypes within this script, were generated with the assumption that only
#	one  or two streams would be active at a time. Additional prototypes would need to be 
#	added for coverage in scenarios beyond two simultaneous connections (could be an issue
#	if the actor is active while transferring multiple large files). Additionally, this 
#	script currently only supports generating signatures for traffic with PI implants 
#	operating in direct connection mode, not via SOCKS or HTTP proxies (rare).
#
#	All generated signatures are for traffic from the C2 server to the affected client
#	since we can not reliably predict what the headers will be from the client. The one 
#	exception is the client heartbeat - this stays consistent and contains no host
#	specific data.
#
#	Limited testing has shown the following signatures to be reliable across different PI 
#	configurations (e.g. persistence, process injection, etc):
#
#	PI init shellcode
#	PI heartbeat(server)
#	PI heartbeat(client)
#	PI command shell
#	
#	The remaining signatures seem to only hit on specific configurations. This may require
#	additional configuration-specific signatures for each password.
#
#	v1.0: 07-Dec-2014
#	v1.0.1: 07-Dec-2014 - Fixed typos, added more signature prototypes.
#	v1.0.2: 08-Dec-2014 - Updated comments with testing findings. Reordered script
#	output accordingly.
#	v1.0.3: 09-Dec-2014 - Added -x options to segregate reliable sigs from experimental
#	v1.1: 12-Dec-2014 - Added option to read traffic from pcap and conduct a dictionary
#	attack if PI implant traffic is detected. Fixed a bunch of bugs.

import camcrypt
import dpkt
import socket
import sys
import time
from binascii import hexlify, unhexlify
from optparse import OptionParser

# This should be updated to reflect the location of your camellia.so
LIBRARY_PATH = '/Users/mariod/malware/camellia.so'

# Load options parsing routine.
parser = OptionParser()
parser.add_option("-p", "--password", dest="password",
                  help="Plaintext Poison Ivy password")
parser.add_option("-k", "--key", dest="key",
                  help="A key in plain hex format")
parser.add_option("-a", "--all",
                  action="store_true", dest="full_sig", default=False,
                  help="Print full Snort signature vice just msg, content and depth (you must edit the SID)")
parser.add_option("-x", "--experimental",
                  action="store_true", dest="experimental", default=False,
                  help="Include experimental signatures")
parser.add_option("-r", "--read", dest="pcap",
                  help="Attempt to crack PI password for supplied PI traffic in PCAP format. If a password or key argument is supplied that password or key will be tried. Additional passwords (but not keys) can be piped in via STDIN")
                  
(options, args) = parser.parse_args()

# Checks if a password or key was supplied, or both and errors out accordingly.
key = ""
if (((not(options.password or options.key)) and not options.pcap) or (options.password and options.key)):
	parser.error("Please provide -p or -k, but not both")
	quit()
if options.key:
	try:
		# Check if provided key is valid hex
		unhexlify(options.key)
		key = options.key
	except:
		parser.error("Not a valid hex key. example valid key: 61646d696e")
		quit()
elif options.password:
	key = options.password.encode('hex')
		
# Setup our signature prototypes.
# This lays out the heart of what we are generating signatures for. Alert message,
# first 16 bytes of network traffic prior to encryption, and an optional prepend for 
# network traffic that will not be encrypted. The 16 byte stubs are based on a data 
# structure described above and were generated by decrypting PI traffic.
prototype = [
			["PI init shellcode []", "558bec50b81000000081c404f0ffff50", "d0150000"],
			["PI heartbeat(server) []", "2700000001000000100000000a000000", ""],
			["PI heartbeat(client) []", "27000000010000001000000008000000", ""],
			["PI command shell []", "17000000010000002000000010000000", ""],
			["PI command shell []", "17000000020000002000000010000000", ""]
			]

prototypeX = 	[
				["PI process listing []", "1400000001000000f0030000e8030000", ""],
				["PI process listing []", "1400000002000000f0030000e8030000", ""],
				["PI connection listing []", "3800000001000000c0020000b6020000", ""],
				["PI connection listing []", "3800000002000000c0020000b6020000", ""],
				["PI hash dump []", "5b000000010000009006000081060000", ""],
				["PI hash dump []", "5b000000020000009006000081060000", ""]
				]

# Popular APT passwords from the appendix to FireEye's PI report.
pw_list = 	["admin","keaidestone","menuPass","admin@338","suzuki","happyyongzi",
				"th3bug","smallfish","XGstone","key@321","xiaoxiaohuli","woaiwojia@12",
				"japanorus","8f1a3e48d01c76a1","abc123!@#","Thankss","1qaz2wsx","key@123",
				"gwx@123","fishplay","aDmin","wwwst@Admin", " ",
				0xfb453847cb12db0d60ce04795e3059633788f131bfc4da1b8f1a3e48d01c76a1]
					
# Our camellia encryption routine. It expects a 16-byte chunk of data.
def camencrypt(plaintext,key):
	# Setting up Camellia
	mycrypt = camcrypt.CamCrypt(LIBRARY_PATH)
	mycrypt.keygen(256, key)
	# Encrypt our protocol prototype after converting it from hex to binary data
	encrypted = mycrypt.encrypt(plaintext)
	return encrypted

# The camellia decryption routine. Expects raw data, not hexlified.	
def camdecrypt(cipher,key):
	# Setting up Camellia
	mycrypt = camcrypt.CamCrypt(LIBRARY_PATH)
	mycrypt.keygen(256, key)
	# Decrypt our protocol artifact after converting it from hex to binary data
	plain = mycrypt.decrypt(cipher)
	return plain

# Defining the workhorse function that handles encryption and signature generation
def build_content(proto, key, full):
	
	# Length checks to avoid overly long alert messages
	if len(key) > 19:
		if options.key:
			msg_key = "key:0x" + hexlify(key[:8]) + "..."
		else:
			msg_key = "key:0x" + hexlify(key[:8]) + "..."
	else:
		if options.key:
			msg_key = "key:0x" + hexlify(key)
		else:
			msg_key = key
			
	# Encrypt our signature prototype bytes
	encrypted = camencrypt(unhexlify(proto[1]),key)
	# Put the encrypted result into hex form 
	enc_hex = hexlify(encrypted)
	# Prepend any unencrypted traffic as defined in the prototype
	enc_hex = proto[2] + enc_hex 
	# Convert our predicted traffic to a more easily format by injecting spaces
	formatted = ' '.join(a+b for a,b in zip(enc_hex[::2], enc_hex[1::2]))
	# Determine the length of our traffic for the depth keyword. Divide the number of
	# chars by 2 to determine how many bytes since its hex-encoded
	depth = str((len(proto[1]) + len(proto[2]))/2)
	# Present a full signature or an abbreviated form based on -a flag
	if full:
		return "alert tcp any any -> any any (msg:\"" + proto[0].replace("[]","[" + msg_key + "]") + "\"; content:\"|" + formatted + "|\"; depth: " + depth + "; sid: 5000001; rev: 1;)"
	else:
		return "msg:\"" + proto[0].replace("[]","[" + msg_key + "]") + "\"; content:\"|" + formatted + "|\"; depth: " + depth

# The control code for the signature building portion. 
def build_sigs(key):
			
	for proto in prototype:          
		print build_content(proto, key, options.full_sig)
	
	if options.experimental:
		for proto in prototypeX:          
			print build_content(proto, key, options.full_sig)

# Our PI password cracking routine. Expects raw data, not hexlified.
def crack(plain, cipher, source):
	key = ""
	keyflag = False
	counter = 0
	total = 0
	print "Attempting password attack on " + source;
	# Try our default password list first
	print "Building password list"
	if options.password:
		pw_list.append(options.password)
		print "Checking built-in passwords and " + options.password
	if options.key:
		pw_list.append(int(options.key,16))
		print "Checking built-in passwords and key 0x" + options.key
	if not sys.stdin.isatty():
		print "Reading from STDIN"
		for pw in sys.stdin.readlines():
			pw = pw.rstrip('\n\r')
			if pw == "":
				continue
			if len(pw) > 32:
				pw = pw[:32]
			pw_list.append(pw)
	print "Trying passwords"
	start = int(time.time())
	for pw in pw_list:
		if isinstance(pw, long):
			pw = unhexlify(str("%x" % pw))
			keyflag = True
		counter += 1
		total += 1
		if counter == 1000:
			sys.stdout.write(".")
			sys.stdout.flush()
			counter = 0; 
		candidate = camdecrypt(cipher[:16],pw)
		if candidate == plain[:16]:
			if keyflag:
				print "Key found: " + hexlify(pw)
			else:
				print "Password found: " + pw
			key = pw
			stop = int(time.time())
			how_long = stop - start
			print "Tried " + str(total) + " passwords in " + str(how_long) + " seconds." 
			break
		keyflag = False
		
	if key:
		build_sigs(key)
		exit()
	else:
		print "No password found"
		stop = int(time.time())
		how_long = stop - start
		print "Tried " + str(total) + " passwords in " + str(how_long) + " seconds." 
		exit
			
# Generates a Snort signature based on an encrypted PI heartbeat	
def unid_PI_sig(data):
	print "Snort signature for possible PI heartbeat: " + hexlify(data)
	print "alert tcp any any -> any any (msg:\"Possible PI heartbeat [UNID]\"; content:\"|" + hexlify(data) + "|\"; depth: 16; sid: 5000001; rev: 1;)"
	exit()

# The routine for extracting the encrypted data from pcap that we want to attack
def process_pcap():

	f = open(options.pcap)
	pcap = dpkt.pcap.Reader(f)
	seqnum1 = 0
	seqnum2 = 0
	heartbeats_one = 0
	heartbeats_two = 0
	hb_candidate_one = ""
	hb_candidate_two = ""

	for ts,buf in pcap:
		eth = dpkt.ethernet.Ethernet(buf)
		if eth.type == 2048:
			ip = eth.data
			if ip.p == 6:
				tcp = ip.data
				# Check to see if we have PI handshake - 256 bytes from client, 256 byte 
				# response from server, and then 1460 byte packet with the magic "d0150000"
				# Threw in some TCP seq number math since dpkt doesn't reassemble the stream
				# for us
				if (len(tcp.data) == 1460 and hexlify(tcp.data[:4]) == "d0150000" and seqnum1 and (tcp.seq - seqnum2 == 256)):
					print "PI handshake found!"
					print socket.inet_ntoa(ip.src) + ":" + str(tcp.sport) + " -> " + socket.inet_ntoa(ip.dst) + ":" + str(tcp.dport)
					# We have a handshake so now try and crack the password
					crack(client_handshake, server_handshake, "handshake")
					exit()
				if (len(tcp.data) == 256 and (tcp.ack - seqnum1 == 256)):
					seqnum2 = tcp.seq
					server_handshake = tcp.data
				if (len(tcp.data) == 256 and not seqnum1):
					seqnum1 = tcp.seq
					client_handshake = tcp.data
				# Below is needed to reset our sequence numbers in case there are some 
				# spurious packets in the capture since we aren't tracking TCP streams.
				if (len(tcp.data) == 1460 and not (seqnum1 and seqnum2)):
					seqnum1 = 0
					seqnum2 = 0
				# At this point no PI handshake was found. That means that either this isn't
				# (standard) PI, or the full handshake is missing from the pcap for some
				# reason (one-sided collection, taking hits, whatever). Let's look for 48-byte
				# TCP payloads that may be PI heartbeats. We will only declare a possible PI
				# heartbeat if we see the same 48-byte TCP payload at least three times.
				# This looks wonky, but seems to work well, at least in testing...
				if (len(tcp.data) == 48 and (heartbeats_one == 2 or heartbeats_two == 2)):
					if (hb_candidate_one == tcp.data):
						print "Poison Ivy heartbeats found."
						print socket.inet_ntoa(ip.src) + ":" + str(tcp.sport) + " -> " + socket.inet_ntoa(ip.dst) + ":" + str(tcp.dport)
						# Try to crack as a server heartbeat
						crack(unhexlify(prototype[1][1]), tcp.data, "server heartbeat")
						# Try to crack as a client heartbeat
						crack(unhexlify(prototype[2][1]), tcp.data, "client heartbeat")
						# If neither cracked then generate an UNID PI Snort sig
						unid_PI_sig(tcp.data[:16])
					if (hb_candidate_two == tcp.data):
						# Try to crack as a server heartbeat
						crack(unhexlify(prototype[1][1]), tcp.data, "server heartbeat")
						# Try to crack as a client heartbeat
						crack(unhexlify(prototype[2][1]), tcp.data, "client heartbeat")
						# If neither cracked then generate an UNID PI Snort sig
						unid_PI_sig(tcp.data[:16])			
				if (len(tcp.data) == 48 and (heartbeats_one == 1 or heartbeats_two == 1)):
					if (hb_candidate_one == tcp.data):
						heartbeats_one += 1
					if (hb_candidate_two == tcp.data):
						heartbeats_two += 1
					else:
						hb_candidate_two = tcp.data
						heartbeats_two = 1
				if (len(tcp.data) == 48 and heartbeats_one == 0):
					hb_candidate_one = tcp.data
					heartbeats_one += 1
									
	# If we have made it this far that means no matches were made either on the handshake or
	# possible PI heartbeats
	print "No PI traffic found!"
	
def main():
    # Are we generating signatures or trying to crack a PI password?
    if options.pcap:
    	process_pcap()
    else:
    	build_sigs(unhexlify(key))

# Do the things...
if __name__ == "__main__":
    main()