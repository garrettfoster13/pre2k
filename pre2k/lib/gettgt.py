from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5 import constants
from impacket.krb5.types import Principal

class GETTGT:
    def __init__(self, username, password, domain, dc_ip):
        self.__password = password
        self.__user = username
        self.__domain = domain
        self.__kdcHost = dc_ip

    def saveTicket(self, ticket, sessionKey):
        logger.info('Saving ticket in %s' % (self.__user + '.ccache'))
        # print('exort KRB5CCNAME=%s' % (os.getcwd()) + self.__user + '.ccache')
        #print('export KRB5CCNAME=%s %s' % (os.getcwd()) % (self.__user + '.ccache'))
        from impacket.krb5.ccache import CCache
        ccache = CCache()

        ccache.fromTGT(ticket, sessionKey, sessionKey)
        ccache.saveFile(self.__user + '.ccache')
        return True

    def run(self, save):
        userName = Principal(self.__user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain, None, None, None, self.__kdcHost)
        if save:
            self.saveTicket(tgt,oldSessionKey)
        return True