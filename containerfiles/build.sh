podman build -f bird.containerfile -t localhost/bird
podman build -f gobgp.containerfile -t localhost/gobgp
podman build -f frr.containerfile -t localhost/frr
