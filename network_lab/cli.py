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


@cli.command("generate-config")
@click.option("-f", "--file", "config_file", required=True, type=click.Path(exists=True),
              help="Path to lab YAML configuration file.")
@click.option("--force", is_flag=True, help="Overwrite existing config files.")
def generate_config(config_file, force):
    """Generate BGP config files for all routers in a lab."""
    config = parse_config(config_file)
    engine.ensure_configs(config, force=force)


@cli.command("show-bgp-peers")
@click.argument("lab_name")
def show_bgp_peers(lab_name):
    """Show BGP peers across all routers in a lab."""
    engine.show_bgp_peers(lab_name)


@cli.command("trace")
@click.argument("lab_name")
@click.argument("src")
@click.argument("dst")
def trace(lab_name, src, dst):
    """Trace path between two IPs showing BGP route details at each hop."""
    engine.trace_path(lab_name, src, dst)
