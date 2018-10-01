from oracle import *
import sys
from binascii import hexlify

if len(sys.argv) < 2:
    print "Usage: python sample.py <filename>"
    sys.exit(-1)

print(sys.argv[1])
f = open(sys.argv[1])
data = f.read()[:-1]
f.close()

if len(data) % 32 != 0:
    data += " " * (32 - (len(data) % 32))
print('trying to spoof the following message: "%s"' % data)

# Cutting message into 32 byte blocks
message = [data[i:i+32] for i in range(0, len(data), 32)]
print message

# Connecting to the oracle
Oracle_Connect()

# Empty base tag
tag = bytearray(16)
for m in message:
    # Make tag as long as m and xor tag_prev with m
    tag += bytearray(16)
    m = [x ^ y for (x, y) in zip(bytearray(m), tag)]
    # Get the tag for m xor tag_prev
    tag = Mac(m, 32)

# The last tag should be the one of the message
print('The final tag: %s' % hexlify(tag))

ret = Vrfy(data, len(data), tag)
print
print ret
if (ret == 1):
    print "Message verified successfully!"
else:
    print "Message verification failed."

Oracle_Disconnect()
print(data)
