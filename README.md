# pre2k

Pre2k is a tool to query for the existence of pre-windows 2000 computer objects which can be leveraged to gain a foothold in a target domain as discovered by [TrustedSec's](https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts/) [@Oddvarmoe](https://twitter.com/Oddvarmoe). Pre2k can be ran from an uanuthenticated context to perform a password spray from a provided list of recovered hostnames (such as from an RPC/LDAP null bind) or from an authenticated context to perform a targeted or broad password spray. Users have the flexibility to target every machine or to stop on the first successful authentication as well as the ability to request and store a valid TGT in .ccache form in their current working directory.

## Installation

```pip3 install -r requirements.txt```


## Usage

```
└─# python3 pre2k.py -h                                                                                                                         


                                ___    __         
                              /'___`\ /\ \        
 _____   _ __    __          /\_\ /\ \\ \ \/'\    
/\ '__`\/\`'__\/'__`\ _______\/_/// /__\ \ , <    
\ \ \L\ \ \ \//\  __//\______\  // /_\ \\ \ \\`\  
 \ \ ,__/\ \_\\ \____\/______/ /\______/ \ \_\ \_\
  \ \ \/  \/_/ \/____/         \/_____/   \/_/\/_/
   \ \_\                                      v2.0    
    \/_/                                          
                                            @garrfoster          



usage: pre2k.py [-h] {unauth,auth} ...

Tool to enumerate a target environment for the presence of machine accounts configured as pre-2000 Windows machines. Either by brute forcing all machine accounts, a targeted, filtered approach, or from a user supplied input list.

positional arguments:
  {unauth,auth}
    unauth       Pass a list of hostnames to test authentication.
    auth         Query the domain for pre Windows 2000 machine accounts.

options:
  -h, --help     show this help message and exit
```

## Unauth

```
└─# python3 pre2k.py unauth -h


                                ___    __         
                              /'___`\ /\ \        
 _____   _ __    __          /\_\ /\ \\ \ \/'\    
/\ '__`\/\`'__\/'__`\ _______\/_/// /__\ \ , <    
\ \ \L\ \ \ \//\  __//\______\  // /_\ \\ \ \\`\  
 \ \ ,__/\ \_\\ \____\/______/ /\______/ \ \_\ \_\
  \ \ \/  \/_/ \/____/         \/_____/   \/_/\/_/
   \ \_\                                      v2.0    
    \/_/                                          
                                            @garrfoster          



usage: pre2k.py unauth [-h] -d  -dc-ip  [-inputfile INPUTFILE] [-outputfile OUTPUTFILE] [-verbose] [-stoponsuccess] [-save]

options:
  -h, --help            show this help message and exit
  -d                    Target domain
  -dc-ip                IP address or FQDN of domain controller
  -inputfile INPUTFILE  Pass a list of machine accounts to validate. Format = 'machinename$'
  -outputfile OUTPUTFILE
                        Log results to file.
  -verbose              Verbose output displaying failed attempts.
  -stoponsuccess        Stop on sucessful authentication
  -save                 Request and save a .ccache file to your current working directory
```

## Auth
```
└─# python3 pre2k.py auth -h  


                                ___    __         
                              /'___`\ /\ \        
 _____   _ __    __          /\_\ /\ \\ \ \/'\    
/\ '__`\/\`'__\/'__`\ _______\/_/// /__\ \ , <    
\ \ \L\ \ \ \//\  __//\______\  // /_\ \\ \ \\`\  
 \ \ ,__/\ \_\\ \____\/______/ /\______/ \ \_\ \_\
  \ \ \/  \/_/ \/____/         \/_____/   \/_/\/_/
   \ \_\                                      v2.0    
    \/_/                                          
                                            @garrfoster          



usage: pre2k.py auth [-h] [-u] [-p] -d  -dc-ip  [-ldaps] [-k] [-no-pass] [-hashes LMHASH:NTHASH] [-aes hex key] [-targeted] [-verbose] [-outputfile OUTPUTFILE] [-stoponsuccess] [-save]

options:
  -h, --help            show this help message and exit
  -u                    Username
  -p                    Password
  -d                    Target domain
  -dc-ip                IP address or FQDN of domain controller
  -ldaps                Use LDAPS instead of LDAP
  -k, --kerberos        Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line
  -no-pass              don't ask for password (useful for -k)
  -hashes LMHASH:NTHASH
                        LM and NT hashes, format is LMHASH:NTHASH
  -aes hex key          AES key to use for Kerberos Authentication (128 or 256 bits)
  -targeted             Search by UserAccountControl=4128. Prone to false positive/negatives but less noisy.
  -verbose              Verbose output displaying failed attempts.
  -outputfile OUTPUTFILE
                        Log results to file.
  -stoponsuccess        Stop on sucessful authentication
  -save                 Request and save a .ccache file to your current working directory
```
