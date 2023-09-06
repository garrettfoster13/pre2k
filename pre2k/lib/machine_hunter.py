from pre2k.logger import console, logger
from pre2k.lib.ldap import get_dn
import ldap3
import json

class MachineHunter:
    
    def __init__(self, ldap_server, ldap_session, domain, targeted):
        self.ldap_server = ldap_server
        self.ldap_session = ldap_session
        self.search_base = get_dn(domain)
        self.attributes = "sAMAccountName"
        self.domain = domain
        self.targeted = targeted

    def fetch_computers(self, ldap_session):
        creds = []
        num = 0
        with console.status(f"Searching...", spinner="dots") as status:
            if self.targeted:
                search_filter = "(&(objectclass=computer)(logonCount=0))"
            else:
                search_filter = "(objectclass=computer)"
            try:
                ldap_session.extend.standard.paged_search(self.search_base, search_filter, attributes=self.attributes, paged_size=500, generator=False)
                # print (f'Retrieved {len(self.ldap_session.entries)} results total.')
            except ldap3.core.exceptions.LDAPAttributeError as e:
                print()
                logger.error (f'Error: {str(e)}')
                exit()
            for entry in ldap_session.entries:
                num += 1
                status.update(f"Retrieved {num} results.")
                json_entry = json.loads(entry.entry_to_json())
                attributes = json_entry['attributes'].keys()
                for attr in attributes:
                    val = entry[attr].value
                    if len(val) >= 15:
                        #if account name is 15 chars or more pw is first 14
                        credentials = val + ":" + val.lower()[:14]
                    else:
                        credentials = val + ":" + val.lower()[:-1]
                    creds.append(credentials)
            logger.info (f'Retrieved {len(self.ldap_session.entries)} results total.')
            return creds
