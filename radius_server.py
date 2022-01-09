#!/usr/bin/python
from __future__ import print_function
import configparser
import logging.config
import logging
from pyrad import dictionary, packet, server
from ldap_authenticator import LdapAuthenticator

logging.config.fileConfig("logging.conf", disable_existing_loggers=False)

logger = logging.getLogger("radius_server")


class RemoteHost(server.RemoteHost):
    def __init__(self, address, secret, name, groups):
        super().__init__(address, secret, name)
        self.groups = groups or []


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
        logger.info("Authenticate user '%s'", username)
        user_authenticated = False
        if username and password:
            (success, msg, fullname, member_of) =\
                self.ldap.authenticate(username, password)
            if success:
                remote_host = self.__get_remote_host__(pkt)
                user_groups = repr(getattr(remote_host, "groups", []))
                if len(user_groups):
                    user_authenticated = any(
                        any(m.startswith(f"CN={g},") for m in member_of)
                        for g in user_groups
                    )
                else:
                    user_authenticated = True
                logger.info(
                    "Authenticated%s '%s'",
                    "" if user_authenticated else " NOT",
                    fullname
                )
                logger.debug("member of %s", repr(member_of))
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
        self.__dump_clients__()
        logger.info("LDAP-Radius server started...")
        return super().Run()

    def __dump_clients__(self):
        logger.info("RADIUS Clients:")
        for address, client in self.hosts.items():
            name = getattr(client, "name", "N/A")
            logger.info("\t'%s':", name)
            logger.info("\t\tAddress: '%s'", address)
            groups = getattr(client, "groups", [])
            logger.info("\t\tUser groups: %s", repr(groups))
            if not len(groups):
                logger.warning(
                    "Client '%s' on '%s' accepts any user group!", name, address)

    def __get_remote_host__(self, pkt: packet.Packet) -> RemoteHost:
        if pkt.source[0] in self.hosts:
            return self.hosts[pkt.source[0]]
        elif '0.0.0.0' in self.hosts:
            return self.hosts['0.0.0.0']
        else:
            raise server.ServerPacketError('Received packet from unknown host')


if __name__ == '__main__':
    config = configparser.ConfigParser()
    config.read("radius_ldap_server.cfg")
    authenticator = LdapAuthenticator(
        config["LDAP"]["ServerAddress"],
        config["LDAP"].get("DCRoot", None),
        float(config["LDAP"]["Timeout"])
    )
    # create server and read dictionary
    radius_dictionary = config["Radius"]["Dictionary"]
    logger.debug("Radius dictionary: '%s'", radius_dictionary)
    addresses = config["Radius"]["Addresses"].split(",")
    logger.debug("Radius addresses: %s", repr(addresses))
    port = int(config["Radius"]["Port"])
    logger.debug("Radius port: %s", port)
    srv = LdapRadiusServer(
        authenticator,
        authport=port,
        dict=dictionary.Dictionary(radius_dictionary)
    )

    # add clients (address, secret, name)
    for client_name in config["Radius"]["Clients"].split(","):
        client_config = config[f"Radius_{client_name}"]
        client_address = client_config["Address"]
        client_secret = client_config["Secret"]
        user_groups = [g for g in client_config["UserGroups"].split(",") if g]
        srv.hosts[client_address] = RemoteHost(
            client_address,
            client_secret.encode(),
            client_name,
            user_groups
        )

    for address in addresses:
        srv.BindToAddress(address)

    # start server
    srv.Run()
