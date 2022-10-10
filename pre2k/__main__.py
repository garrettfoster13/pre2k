import typer
from pre2k.logger import init_logger, logger, console
from pre2k import __version__
from pre2k.lib.commands import auth, unauth

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode='rich',
    context_settings={'help_option_names': ['-h', '--help']},
    pretty_exceptions_show_locals=False
)

app.add_typer(
    auth.app,
    name=auth.COMMAND_NAME,
    help=auth.HELP
)

app.add_typer(
    unauth.app,
    name=unauth.COMMAND_NAME,
    help=unauth.HELP
)


if __name__ == '__main__':
    app(prog_name='pre2k')