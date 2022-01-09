#!/usr/bin/python
from __future__ import print_function
from pyrad import dictionary, packet, server
import logging
import logging.config
from ldap_authenticator import LdapAuthenticator

logging.config.fileConfig("logging.conf")
# logging.basicConfig(
#    # filename="pyrad.log",
#    level="DEBUG",
#    format="%(asctime)s [%(levelname)-8s] %(message)s"
# )

logger = logging.getLogger("radius_server")


class LdapRadiusServer(server.Server):
    def __init__(self, ldapAuthenticator: LdapAuthenticator, addresses=[], authport=1812, hosts=None, dict=None):
        super().__init__(
            addresses=addresses,
            authport=authport,
            hosts=hosts,
            dict=dict,
            auth_enabled=True,
            acct_enabled=False,
            coa_enabled=False
        )
        self.ldap = ldapAuthenticator

    def HandleAuthPacket(self, pkt: packet.AuthPacket):
        logger.info("Received an authentication request")
        logger.debug("Attributes: ")
        for attr in pkt.keys():
            logger.debug("\t%s: %s", attr, pkt[attr])
        username = (
            pkt["User-Name"][0]
            if "User-Name" in pkt.keys() and len(pkt["User-Name"])
            else None
        )
        password = (
            pkt.PwDecrypt(pkt["User-Password"][0])
            if "User-Password" in pkt.keys() and len(pkt["User-Password"])
            else None
        )
        logger.info("Authenticate user %s", username)
        user_authenticated = False
        if username and password:
            (success, msg, fullname, groups) =\
                (True, "Succ", "FN", ["VPN"])
            #self.ldap.authenticate(username, password)
            if success:
                logger.info("Authenticated %s", fullname)
                logger.debug("member of %s", repr(groups))
                user_authenticated = True
            else:
                logger.error(msg)
        else:
            logger.error("username or password is missing")

        reply = self.CreateReplyPacket(pkt, **{
            "Service-Type": "Framed-User",
        })

        reply.code = (
            packet.AccessAccept
            if user_authenticated
            else packet.AccessReject
        )
        self.SendReplyPacket(pkt.fd, reply)

    def BindToAddress(self, addr):
        logger.info("Listening on: ")
        addrFamily = self._GetAddrInfo(addr)
        for _, address in addrFamily:
            logger.info("\t%s:%d", address, self.authport)
        return super().BindToAddress(addr)

    def Run(self):
        logger.info("RADIUS Clients:")
        for k, v in self.hosts.items():
            logger.info("\t%s: %s", k, getattr(v, "name", "N/A"))
        logger.info("server started")
        return super().Run()


if __name__ == '__main__':

    # create server and read dictionary
    srv = LdapRadiusServer(
        None, dict=dictionary.Dictionary("radius_dictionary")
    )

    # add clients (address, secret, name)
    srv.hosts["0.0.0.0"] = server.RemoteHost(
        "0.0.0.0",
        b"Kah3choteereethiejeimaeziecumi",
        "localhost"
    )
    srv.BindToAddress("0.0.0.0")

    # start server
    srv.Run()
