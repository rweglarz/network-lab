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
@click.option("--graph", "-g", "graph_output", default=None,
              help="Generate graph with traced path highlighted (output file).")
@click.option("--png", is_flag=True, help="Output graph as PNG instead of SVG.")
def trace(lab_name, src, dst, graph_output, png):
    """Trace path between two IPs showing BGP route details at each hop."""
    forward_hops, backward_hops = engine.trace_path(lab_name, src, dst)
    if graph_output:
        from network_lab.graph import generate_trace_graph
        fmt = "png" if png else "svg"
        generate_trace_graph(lab_name, forward_hops, backward_hops,
                             output=graph_output, fmt=fmt)


@cli.command("generate-graph")
@click.argument("lab_name")
@click.option("-o", "--output", default=None,
              help="Output file path (png/svg/pdf). Shows interactively if omitted.")
@click.option("--png", is_flag=True, help="Output as PNG instead of SVG.")
def generate_graph(lab_name, output, png):
    """Generate visual representation of the network topology."""
    from network_lab.graph import generate_graph as _generate_graph
    fmt = "png" if png else "svg"
    _generate_graph(lab_name, output=output, fmt=fmt)


@cli.command("disable-peer")
@click.argument("lab_name")
@click.argument("router_a")
@click.argument("router_b")
def disable_peer(lab_name, router_a, router_b):
    """Disable BGP session between two routers."""
    engine.disable_peer(lab_name, router_a, router_b)


@cli.command("enable-peer")
@click.argument("lab_name")
@click.argument("router_a")
@click.argument("router_b")
def enable_peer(lab_name, router_a, router_b):
    """Enable BGP session between two routers."""
    engine.enable_peer(lab_name, router_a, router_b)


@cli.command("reload-config")
@click.argument("lab_name")
@click.argument("router_name", required=False, default=None)
def reload_config(lab_name, router_name):
    """Reload BGP config on a router (or all routers) from local config files."""
    engine.reload_config(lab_name, router_name)


@cli.command("enable-all-peers")
@click.argument("lab_name")
def enable_all_peers(lab_name):
    """Re-enable all administratively disabled BGP sessions."""
    engine.enable_all_peers(lab_name)
