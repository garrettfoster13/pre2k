import typer
from pre2k.lib.pre_2k import Pre2k

app = typer.Typer()
COMMAND_NAME = 'unauth'
HELP = 'Pass a list of hostnames to test authentication.'

@app.callback(no_args_is_help=True, invoke_without_command=True)
def main(
    domain          : str               = typer.Option(..., '-d',  help="Target domain"),
    dc_ip           : str               = typer.Option(..., '-dc-ip',  help = "IP address or FQDN of domain controller"),
    verbose         : bool              = typer.Option(False, "-verbose", help="Verbose output displaying failed attempts."),
    inputfile       : typer.FileText    = typer.Option(..., "-inputfile", help="Pass a list of machine accounts to validate. Format machinename$"),
    outputfile      : str               = typer.Option(None, "-outputfile", help="Log results to file."),
    stop_on_success : bool              = typer.Option(False, "-stoponsuccess", help="Stop on sucessful authentication"),
    save            : bool              = typer.Option(False, "-save", help="Request and save a .ccache file to your current working directory"),
    empty_pass      : bool              = typer.Option(False, "-n", help="Attempt authentication with an empty password."),
    sleep           : int               = typer.Option(None, "-sleep", help="Length of time to sleep between attempts in seconds."),
    jitter          : int               = typer.Option(None, "-jitter", help="Add jitter to sleep time."),
    threads         : int               = typer.Option(10, "-threads", help="Number of threads to spray with. Default: 10")):

    pre2k = Pre2k(domain=domain, dc_ip=dc_ip, verbose=verbose, inputfile=inputfile,
                    outputfile=outputfile, stop_on_success=stop_on_success, save=save,
                    empty_pass=empty_pass, sleep=sleep, jitter=jitter, threads=threads, 
                    authenticated=False)
    pre2k.run()