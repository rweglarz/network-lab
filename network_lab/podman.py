import json
import subprocess


class PodmanError(Exception):
    pass


class Podman:
    """Wrapper around the podman CLI."""

    def _run(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        cmd = ["podman", *args]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if check and result.returncode != 0:
            raise PodmanError(result.stderr.strip())
        return result

    # Networks

    def network_create(self, name: str, *, labels: dict[str, str] | None = None,
                       internal: bool = False, disable_dns: bool = False,
                       ipam_driver: str | None = None) -> None:
        cmd = ["network", "create"]
        if internal:
            cmd.append("--internal")
        if disable_dns:
            cmd.append("--disable-dns")
        if ipam_driver:
            cmd.extend(["--ipam-driver", ipam_driver])
        for key, value in (labels or {}).items():
            cmd.extend(["--label", f"{key}={value}"])
        cmd.append(name)
        self._run(*cmd)

    def network_exists(self, name: str) -> bool:
        result = self._run("network", "exists", name, check=False)
        return result.returncode == 0

    def network_list(self, *, label: str | None = None) -> list[str]:
        cmd = ["network", "ls", "--format", "{{.Name}}"]
        if label:
            cmd.extend(["--filter", f"label={label}"])
        result = self._run(*cmd)
        return [n for n in result.stdout.strip().splitlines() if n]

    def network_remove(self, name: str) -> None:
        self._run("network", "rm", "-f", name, check=False)

    def network_connect(self, network: str, container: str) -> None:
        self._run("network", "connect", network, container)

    # Containers

    def container_run(self, image: str, *, name: str, hostname: str,
                      labels: dict[str, str] | None = None,
                      cap_add: list[str] | None = None,
                      network: str | None = None,
                      volumes: list[str] | None = None,
                      command: list[str] | None = None) -> None:
        cmd = ["run", "-d", "--name", name, "--hostname", hostname]
        for key, value in (labels or {}).items():
            cmd.extend(["--label", f"{key}={value}"])
        for cap in (cap_add or []):
            cmd.extend(["--cap-add", cap])
        if network:
            cmd.extend(["--network", network])
        for vol in (volumes or []):
            cmd.extend(["-v", vol])
        cmd.append(image)
        cmd.extend(command or [])
        self._run(*cmd)

    def container_list(self, *, label: str | None = None) -> list[dict]:
        cmd = ["ps", "-a", "--format", "json"]
        if label:
            cmd.extend(["--filter", f"label={label}"])
        result = self._run(*cmd)
        if not result.stdout.strip():
            return []
        return json.loads(result.stdout)

    def container_remove(self, name: str) -> None:
        self._run("rm", "-f", name, check=False)

    def container_exec(self, container: str, command: list[str]) -> subprocess.CompletedProcess:
        return self._run("exec", container, *command, check=True)
