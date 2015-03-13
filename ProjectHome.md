Useful for generating Snort signature content for known PI passwords and conducting dictionary attacks against traffic from implants using an unknown password.

```
$ ./pivysnort.py -h
Usage: pivysnort.py [options]

Options:
  -h, --help            show this help message and exit
  -p PASSWORD, --password=PASSWORD
                        Plaintext Poison Ivy password
  -k KEY, --key=KEY     A key in plain hex format
  -a, --all             Print full Snort signature vice just msg, content and
                        depth (you must edit the SID)
  -x, --experimental    Include experimental signatures
  -r PCAP, --read=PCAP  Attempt to crack PI password for supplied PI traffic
                        in PCAP format. If a password or key argument is
                        supplied that password or key will be tried.
                        Additional passwords (but not keys) can be piped in
                        via STDIN

$ ./john --wordlist=/Users/mariod/10kpass.txt --rules --stdout | ~/malware/pivysnort/pivysnort.py -r ~/whiskey_14.pcap 
PI handshake found!
10.0.0.23:443 -> 10.0.0.25:1036
Attempting password attack on handshake
Building password list
Reading from STDIN
words: 422754  time: 0:00:00:00 DONE (Fri Dec 12 00:49:12 2014)  w/s: 2013K  current: Eypheding
Trying passwords
..........Password found: whiskey_14
Tried 10025 passwords in 0 seconds.
msg:"PI init shellcode [whiskey_14]"; content:"|d0 15 00 00 b4 c6 91 0c 46 53 47 01 0a 7b e8 bf 83 5a 07 30|"; depth: 20
msg:"PI heartbeat(server) [whiskey_14]"; content:"|7a 05 66 b5 77 f1 05 97 84 6c 54 8c 02 d0 4e 8b|"; depth: 16
msg:"PI heartbeat(client) [whiskey_14]"; content:"|eb 36 51 67 99 3f b3 50 57 e3 27 a7 f9 d2 29 17|"; depth: 16
msg:"PI command shell [whiskey_14]"; content:"|24 5b 1d e3 81 7e d8 ad fe 93 72 4a 0e b6 75 53|"; depth: 16
msg:"PI command shell [whiskey_14]"; content:"|ea cb ec a1 f3 39 e5 a9 49 4a a7 f6 a6 09 58 56|"; depth: 16

$ ./pivysnort.py -axp menuPass
alert tcp any any -> any any (msg:"PI heartbeat(server) [menuPass]"; content:"|3f 26 68 81 17 0b 39 b2 07 47 91 09 a0 94 63 c4|"; depth: 16; sid: 5000001; rev: 1;)
alert tcp any any -> any any (msg:"PI heartbeat(client) [menuPass]"; content:"|6f 07 53 d1 fe f4 e1 3f 70 2d 10 c8 0b 38 e0 d6|"; depth: 16; sid: 5000001; rev: 1;)
alert tcp any any -> any any (msg:"PI command shell [menuPass]"; content:"|43 87 f2 ad 5c 3b b0 43 40 e1 a7 2b 38 92 0c b2|"; depth: 16; sid: 5000001; rev: 1;)
alert tcp any any -> any any (msg:"PI command shell [menuPass]"; content:"|f8 a8 eb 84 b2 02 a6 e3 2a 54 36 88 23 d2 ec ac|"; depth: 16; sid: 5000001; rev: 1;)
alert tcp any any -> any any (msg:"PI process listing [menuPass]"; content:"|cf f9 5c 63 b1 cb 2d 8a 4b 12 15 31 21 d5 f9 bc|"; depth: 16; sid: 5000001; rev: 1;)
alert tcp any any -> any any (msg:"PI process listing [menuPass]"; content:"|8c 5d 17 da fc e0 9b 23 b7 60 52 af 04 bc a8 4f|"; depth: 16; sid: 5000001; rev: 1;)
alert tcp any any -> any any (msg:"PI connection listing [menuPass]"; content:"|58 fe b9 57 bd 80 30 1c d3 fc fa 75 11 fc 8c c0|"; depth: 16; sid: 5000001; rev: 1;)
alert tcp any any -> any any (msg:"PI connection listing [menuPass]"; content:"|3e fe 15 83 d8 bb 2f 69 8d ad 63 4d 6a 98 e0 b7|"; depth: 16; sid: 5000001; rev: 1;)
alert tcp any any -> any any (msg:"PI hash dump [menuPass]"; content:"|4c 36 d9 77 5e a3 44 86 e9 8c ef 74 92 10 b8 40|"; depth: 16; sid: 5000001; rev: 1;)
alert tcp any any -> any any (msg:"PI hash dump [menuPass]"; content:"|08 09 e0 33 aa 6c 03 4a ec ea 94 77 01 cc bf bc|"; depth: 16; sid: 5000001; rev: 1;)
alert tcp any any -> any any (msg:"PI init shellcode [menuPass]"; content:"|d0 15 00 00 c9 da 2c fa 7a 3d 58 ba 9f f2 d2 a4 c7 b2 b9 4d|"; depth: 20; sid: 5000001; rev: 1;)
```

Logo courtesy of http://mrpotatochips2106.deviantart.com/