#!/usr/bin/python
from __future__ import print_function
import configparser
import logging.config
import logging
from pyrad import dictionary, packet, server
from ldap_authenticator import LdapAuthenticator

logging.config.fileConfig("logging.conf", disable_existing_loggers=False)

logger = logging.getLogger("radius_server")


class LdapRadiusServer(server.Server):
    def __init__(self, ldapAuthenticator: LdapAuthenticator, user_groups=[], addresses=[], authport=1812, hosts=None, dict=None):
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
        if not self.ldap:
            msg = "Missing LDAP authenticator"
            logger.critical(msg)
            raise ValueError(msg)
        self.user_groups = user_groups
        if not len(self.user_groups):
            logger.warning("User groups are not set!")

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
                self.ldap.authenticate(username, password)
            if success:
                if len(self.user_groups):
                    user_authenticated = any(
                        any(m.startswith(f"CN={g},") for m in groups)
                        for g in self.user_groups
                    )
                else:
                    user_authenticated = True
                logger.info("Authenticated%s %s",
                            "" if user_authenticated else " NOT", fullname)
                logger.debug("member of %s", repr(groups))
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
        logger.info("LDAP-Radius server started...")
        return super().Run()


if __name__ == '__main__':
    config = configparser.ConfigParser()
    config.read("radius_ldap_server.cfg")
    authenticator = LdapAuthenticator(
        config["LDAP"]["ServerAddress"],
        config["LDAP"]["DCRoot"],
        float(config["LDAP"]["Timeout"])
    )
    user_groups = [g for g in config["LDAP"]["UserGroups"].split(",") if g]
    logger.debug("Enabled user groups: %s", user_groups)
    # create server and read dictionary
    radius_dictionary = config["Radius"]["Dictionary"]
    logger.debug("Radius dictionary: %s", radius_dictionary)
    addresses = config["Radius"]["Addresses"].split(",")
    logger.debug("Radius addresses: %s", repr(addresses))
    port = int(config["Radius"]["Port"])
    logger.debug("Radius port: %s", port)
    srv = LdapRadiusServer(
        authenticator,
        authport=port,
        user_groups=user_groups,
        dict=dictionary.Dictionary(radius_dictionary)
    )

    # add clients (address, secret, name)
    for client_name in config["Radius"]["Clients"].split(","):
        client_address = config[f"Radius_{client_name}"]["Address"]
        client_secret = config[f"Radius_{client_name}"]["Secret"]
        srv.hosts[client_address] = server.RemoteHost(
            client_address,
            client_secret.encode(),
            client_name
        )

    for address in addresses:
        srv.BindToAddress(address)

    # start server
    srv.Run()
