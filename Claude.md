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
- generate the gobgp or bird or frr config file according to the required router type
- if the bgp config file for the node does not exist yet, generate it. If it does, use the existing one. Add a command to force the regeneration of the file
- the bgp config files sould be stored in "configs" folder with a subfolder for each lab
- in the peers section interpret "as_prepend" as all route exports between the peers should be prepended this way (azure virtual wan behavior for hub-hub route exchange)
- the networks sections should represent a prefix that will be redistributed by the local router with respective community. The router should have a (loopback/dummmy) interface and use the first IP in the prefix

cli requirements:
- show-bgp-peers - show bgp peers in all routers in a format abstracted from underlying bgp daemon
- generate-graph - generates visual representation of the topology with requirements below
- trace - trace path between two ips, use "ip route get" and corresponding bgp daemon command to show selected path details (AS path, cost/metric/preference). Output should be similar to one below. If multiple paths apply show all of them. 
  - example: <hop number if different from prev> <next router name> <prefix> <as path> <cost etc>
  - compare if forward and backward paths use the same routers, if not explicitly indicate / alert on this
  - should have graph option to overlay the path over the graph

graph requirements:
- if the element of topology has "graph_pos" - use this to place the element exactly at location
- draw a box around routers with the same ASN number
- draw in red links/bgp peers that are down
- if the router has networks associated to it put them on a graph next to it


other:
- do not add Co-Authored-By to each commit, we both know you did it
