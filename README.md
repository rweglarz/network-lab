python tool to create container based network labs

Requires podman.
Use the build.sh command to build container images beforehand

# basic usage
## restart lab
```
uv run nl stop vwan; rm configs/vwan/*conf; uv run nl start -f examples/vwan.yml
```

## status check
```
uv run nl show-bgp-peers vwan
podman exec -it nl-vwan-prisma-us-east ip route
podman exec -it nl-vwan-prisma-eu-west vtysh -c "show bgp ipv4 unicast 172.16.111.1"
podman exec -it nl-vwan-prisma-eu-west vtysh -c "show bgp ipv4 unicast 172.16.111.1"
```

## trace
```
uv run nl trace vwan 172.18.211.1 172.16.111.1
```
