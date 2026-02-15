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
- generate the gobgp or bird config file according to the required router type
- if the bgp config file for the node does not exist yet, generate it. If it does, use the existing one. Add a command to force the regeneration of the file
- the bgp config files sould be stored in "configs" folder with a subfolder for each lab
- in the peers section interpret "as_prepend" as all route exports between the peers should be prepended this way (azure virtual wan behavior for hub-hub route exchange)

cli requirements:
- show-bgp-peers - show bgp peers in all routers in a format abstracted from underlying bgp daemon

other:
- do not add Co-Authored-By to each commit, we both know you did it
