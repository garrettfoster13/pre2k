import typer
from pre2k.lib.pre_2k import Pre2k

app = typer.Typer()
COMMAND_NAME = 'auth'
HELP = 'Query the domain for pre Windows 2000 machine accounts.'

@app.callback(no_args_is_help=True, invoke_without_command=True)
def main(
    username        : str   = typer.Option(None, "-u",  help="Username"),
    password        : str   = typer.Option(None, '-p',  help="Password"),
    domain          : str   = typer.Option(..., '-d',  help="Domain"),
    target_dom      : str   = typer.Option(None, '-t', help="Target domain"),
    dc_ip           : str   = typer.Option(..., '-dc-ip',  help = "IP address or FQDN of domain controller"),
    ldaps           : bool  = typer.Option(False, '-ldaps', help='Use LDAPS instead of LDAP'),
    binding         : bool  = typer.Option(False, '-binding', help='Use LDAPS channel binding'),
    kerberos        : bool  = typer.Option(False, "-k", help='Use Kerberos authentication'),
    no_pass         : bool  = typer.Option(False, "-no-pass", help="don't ask for password (useful for -k)"),
    hashes          : str   = typer.Option(None, "-hashes",metavar="LMHASH:NTHASH", help="LM and NT hashes, format is LMHASH:NTHASH",),
    aes             : str   = typer.Option(None, '-aes', metavar="HEX KEY", help='AES key to use for Kerberos Authentication (128 or 256 bits)'),
    targeted        : bool  = typer.Option(False, '-targeted', help="Search for computer accounts with lastlogontimestamp not set"),
    verbose         : bool  = typer.Option(False, "-verbose", help="Verbose output displaying failed attempts."),
    outputfile      : str   = typer.Option(None, "-outputfile", help="Log results to file."),
    stop_on_success : bool  = typer.Option(False, "-stoponsuccess", help="Stop on sucessful authentication"),
    save            : bool  = typer.Option(False, "-save", help="Request and save a .ccache file to your current working directory"),
    empty_pass      : bool  = typer.Option(False, "-n", help="Attempt authentication with an empty password."),
    sleep           : int   = typer.Option(None, "-sleep", help="Length of time to sleep between attempts in seconds."),
    jitter          : int   = typer.Option(None, "-jitter", help="Add jitter to sleep time."),
    threads         : int   = typer.Option(10, "-threads", help="Number of threads to spray with. Default: 10")):

   pre2k = Pre2k(username=username, password=password, domain=domain, target_dom=target_dom, dc_ip=dc_ip, verbose=verbose,
                    ldaps=ldaps, binding=binding, kerberos=kerberos, no_pass=no_pass, hashes=hashes, aes=aes, targeted=targeted,
                    outputfile=outputfile, stop_on_success=stop_on_success, save=save,
                    empty_pass=empty_pass, sleep=sleep, jitter=jitter, threads=threads)
   pre2k.run()
