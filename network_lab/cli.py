import click

from network_lab.config import parse_config
from network_lab import engine


@click.group()
def cli():
    """Network Lab - container-based network topology tool."""


@cli.command()
@click.option("-f", "--file", "config_file", required=True, type=click.Path(exists=True),
              help="Path to lab YAML configuration file.")
def start(config_file):
    """Start a lab from a YAML configuration file."""
    config = parse_config(config_file)
    engine.start(config)


@cli.command()
@click.argument("lab_name")
def stop(lab_name):
    """Stop and clean up a running lab."""
    engine.stop(lab_name)


@cli.command()
@click.argument("lab_name")
def restart(lab_name):
    """Restart a lab (stop then start using stored config)."""
    engine.restart(lab_name)


@cli.command("list")
@click.argument("lab_name")
def list_cmd(lab_name):
    """List containers in a lab."""
    engine.list_containers(lab_name)
