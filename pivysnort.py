#!/usr/bin/env python

#	pivysnort.py v1.0.2 by Mario R. De Tore, SLAC National Laboratory
#	
#	Leverages camcrypt to generate Snort signature content for known PI passwords.
#	https://github.com/knowmalware/camcrypt
#
#	Usage: pivysnort.py [options]
#
#	Options:
#		-h, --help				show this help message and exit
#		-p PASSWORD, --password=PASSWORD
#							plaintext Poison Ivy password
#		-k KEY, --key=KEY			a key in plain hex format
#		-a, --all				print full Snort signature vice just msg, content and
#							depth (you must edit the SID)
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

import binascii
import camcrypt

# This should be updated to reflect the location of your camellia.so
LIBRARY_PATH = '/Users/mariod/malware/camellia.so'

# Load options parsing routine
from optparse import OptionParser

parser = OptionParser()
parser.add_option("-p", "--password", dest="password",
                  help="plaintext Poison Ivy password")
parser.add_option("-k", "--key", dest="key",
                  help="a key in plain hex format")
parser.add_option("-a", "--all",
                  action="store_true", dest="full_sig", default=False,
                  help="print full Snort signature vice just msg, content and depth (you must edit the SID)")

(options, args) = parser.parse_args()
# Checks if a password or key was supplied, or both and errors out accordingly
if ((not(options.password or options.key)) or (options.password and options.key)):
	parser.error("please provide -p or -k, but not both")
	quit()
if options.key:
	try:
		# Check if provided key is valid hex
		key = binascii.unhexlify(options.key)
	except:
		parser.error("not a valid hex key. example valid key: 61646d696e")
		quit()
else:    
	key = options.password

# Length checks to avoid overly long alert messages
if len(key) > 15:
	if options.key:
		msg_key = "key:" + binascii.hexlify(key)[:15] + "..."
	else:
		msg_key = key[:15] + "..."
else:
	if options.key:
		msg_key = "key:" + binascii.hexlify(key)
	else:
		msg_key = key

# This lays out the heart of what we are generating signatures for. Alert message,
# first 16 bytes of network traffic prior to encryption, and an optional prepend for 
# network traffic that will not be encrypted. The 16 byte stubs are based on a data 
# structure described above and were generated by decrypting PI traffic.

prototype = [
			["PI init shellcode [" + msg_key + "]", "558bec50b81000000081c404f0ffff50", "d0150000"],
			["PI heartbeat(server) [" + msg_key + "]", "2700000001000000100000000a000000", ""],
			["PI heartbeat(client) [" + msg_key + "]", "27000000010000001000000008000000", ""],
			["PI command shell [" + msg_key + "]", "16000000010000007002000069020000", ""],
			["PI command shell [" + msg_key + "]", "16000000020000007002000069020000", ""],
			["PI process listing [" + msg_key + "]", "1400000001000000f0030000e8030000", ""],
			["PI process listing [" + msg_key + "]", "1400000002000000f0030000e8030000", ""],
			["PI connection listing [" + msg_key + "]", "3800000001000000c0020000b6020000", ""],
			["PI connection listing [" + msg_key + "]", "3800000002000000c0020000b6020000", ""],
			["PI hash dump [" + msg_key + "]", "5b000000010000009006000081060000", ""],
			["PI hash dump [" + msg_key + "]", "5b000000020000009006000081060000", ""]
            ]

# Defining the workhorse function that handles encryption and signature generation
def build_content(proto, key, path, full):

	# Setting up Camellia
	mycrypt = camcrypt.CamCrypt(path)
	mycrypt.keygen(256, key)
	# Encrypt our protocol artifact after converting it from hex to binary data
	encrypted = mycrypt.encrypt(binascii.unhexlify(proto[1]))
	# Put the encrypted result into hex form 
	enc_hex = binascii.hexlify(encrypted)
	# Prepend any unencrypted traffic as defined in the prototype
	enc_hex = proto[2] + enc_hex 
	# Convert our predicted traffic to a more easily format by injecting spaces
	formatted = ' '.join(a+b for a,b in zip(enc_hex[::2], enc_hex[1::2]))
	# Determine the length of our traffic for the depth keyword. Divide the number of
	# chars by 2 to determine how many bytes since its hex-encoded
	depth = str((len(proto[1]) + len(proto[2]))/2)
	# Present a full signature or an abbreviated form based on -a flag
	if full:
		return "alert tcp any any -> any any (msg:\"" + proto[0] + "\"; content:\"|" + formatted + "|\"; depth: " + depth + "; sid: 5000001; rev: 1;)"
	else:
		return "msg:\"" + proto[0] + "\"; content:\"|" + formatted + "|\"; depth: " + depth

# Do the things...		
for proto in prototype:          
	print build_content(proto, key, LIBRARY_PATH, options.full_sig)
