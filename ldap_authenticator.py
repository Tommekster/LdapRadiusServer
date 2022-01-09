from typing import Any, Dict, List, Tuple
import ldap
import logging

from ldap.ldapobject import LDAPObject

logger = logging.getLogger(__name__)


class LdapAuthenticator:
    def __init__(self, server_address: str, dc_root: str) -> None:
        """
        Parameters:
            server_address : ldap://mydomain.org OR ldap://10.0.0.1
            dc_root        : dc=mydomain,dc=org
        """
        self.server_address = server_address
        self.dc_root = dc_root
        pass

    def authenticate(self, username: str, password: str):
        """
        authenticate(username, password)

        Parameters:
            username
            password

        Returns:
            (success:bool, message:str, user_fullname:Optional[str], member_of:Optional[List[str]])
        """
        logger.info("Contacting %s", self.server_address)
        conn = ldap.initialize(self.server_address)
        conn.protocol_version = 3
        conn.set_option(ldap.OPT_REFERRALS, 0)
        try:
            logger.info("Verify user: %s", username)
            conn.simple_bind_s(username, password)
            logger.info("User %s logged in", username)
            user_info = self.__get_user_info__(conn, username)
            if not user_info:
                return self.__fail__("User not found")
            user_fullname, member_of = self.__parse_user_info__(user_info)
            return True, "Succesfully authenticated", user_fullname, member_of

        except ldap.INVALID_CREDENTIALS:
            return self.__fail__("Invalid credentials")
        except ldap.SERVER_DOWN:
            return self.__fail__("Server down")
        except ldap.LDAPError as e:
            if type(e.message) == dict and e.message.has_key('desc'):
                return self.__fail__("Other LDAP error: " + e.message['desc'], exc_info=True)
            else:
                return self.__fail__("Other LDAP error: " + e, exc_info=True)
        except Exception as e:
            logger.exception(e)
            return False, None, None, None
        finally:
            conn.unbind_s()

    def __get_user_info__(self, conn: LDAPObject, username: str) -> Dict[str, Any]:
        logger.debug("Searching user %s", username)
        query = conn.search_s(
            f"cn=Users,{self.dc_root}",
            ldap.SCOPE_SUBTREE,
            f"(&(objectClass=user)(userPrincipalName={username}))",
            ["name", "memberOf"]
        )
        logger.debug("query has %d results", len(query))
        user_info = next(entry for dn, entry in query if dn)
        return user_info

    def __parse_user_info__(self, user_info: Dict[str, Any]) -> Tuple[str, List[str]]:
        user_fullname = (
            user_info["name"][0].decode()
            if "name" in user_info and len(user_info["name"])
            else "N/A"
        )
        logger.info("Found user %s", user_fullname)
        member_of = (
            [x.decode() for x in user_info["memberOf"]]
            if "memberOf" in user_info
            else []
        )
        logger.info("Member of %s", ";".join(member_of))
        return user_fullname, member_of

    def __fail__(self, message, exc_info=False) -> Tuple[bool, str, None, None]:
        logger.error(message, exc_info=exc_info)
        return False, message, None, None
