from __future__ import print_function
from pyrad.client import Client
from pyrad.dictionary import Dictionary
import pyrad.packet

srv = Client(
    server="127.0.0.1",
    secret=b"Kah3choteereethiejeimaeziecumi",
    dict=Dictionary("radius_dictionary")
)

# create request
req = srv.CreateAuthPacket(code=pyrad.packet.AccessRequest,
                           User_Name="wichert", NAS_Identifier="localhost")
req["User-Password"] = req.PwCrypt("password")

# send request
reply = srv.SendPacket(req)

if reply.code == pyrad.packet.AccessAccept:
    print("access accepted")
else:
    print("access denied")

print("Attributes returned by server:")
for i in reply.keys():
    print("%s: %s" % (i, reply[i]))
