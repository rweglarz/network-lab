Project building network topologies based on containers and podman

requirements:
- implement in python
- read lab configuration from a yml file
- create necessary networks in podman, prefixed with "nl"
- example yml file is in examples/vwan.yml
- after lab is brought down, clean up the networks
- if the name of the lab contains spaces replace them with hyphen
- start necessary containers execute necessary ip addr and ip link commands to configure networking interfaces
- the tool should have basic commands like:
  - start -f examples/vwan.yml
  - stop vwan-lab
  - restart vwan-lab
  - list containers vwan-lab


other:
- do not add Co-Authored-By to each commit, we both know you did it
