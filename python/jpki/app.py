# -*- coding: utf-8 -*-

from . import __version__

import click

@click.group()
@click.version_option(version=__version__)
@click.option('-v', '--verbose', count=True)
@click.pass_context
def cli(ctx, verbose):
    ctx.obj = {}

@cli.command(help='show cert')
@click.pass_context
def cert(ctx):
    pass

@cli.command(help='sign')
@click.pass_context
def sign(ctx):
    pass
