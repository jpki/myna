# -*- coding: utf-8 -*-

from . import __version__

import click

@click.group()
@click.version_option(prog_name='jpki', version=__version__)
@click.option('-v', '--verbose', count=True)
@click.pass_context
def cli(ctx, verbose):
    ctx.obj = {}

@cli.command(help='show cert')
def show_sign_cert(ctx):
    pass
