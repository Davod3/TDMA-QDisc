# Instructions

## Prerequisites

- `sudo apt-get install libnl-3-dev`

- `sudo apt-get install libnl-genl-3-dev`


## Compilation

- `make` - Compiles all kernel modules and the Netcntlr configuration program.

- `make netcntlr` - Compiles the Netcntlr configuration program.

- `make install` - Inserts the compiled modules into the kernel.

- `make remove` - Removes the installed kernel modules.

- `make clean` - Cleans the files created in the compilation process.

## Instalation

1. Create or edit a configuration file in the **Netcntlr** directory;
2. Go to the **scripts/utils** folder;
3. Install the QDisc with `./add_qdisc.sh <path_to_config>`;

## Removal

1. Go to the **scripts/utils** folder;
2. Remove the QDisc with `./remove_qdisc.sh <path_to_config>`;

## Configuration

Several configuration parameters are available. These are:

- **devname** - Name of the network interface to attach the QDisc;

- **node_id** - The ID of the node in the network. Must be unique;

- **slot_size** - The size of a given slot within the TDMA round;

- **limit** - The maximum number of packets that can be held in the Queue;

- **use_guard [0,1]** - Whether or not slots should have a guard time;

- **self_configured [0,1]** - Whether or not the network should try to configure itself using the Topology Tracking module;

- **broadcast_port** - The UDP port to be used in Topology Broadcast Packets;

- **clockless_sync [0,1]** - Whether or not the network should try to sync itself using the RA-TDMA module;

- **n_nodes** - The expected number of nodes in the network - **REQUIRED ONLY IF self_configured==0, OTHERWISE IGNORED** 

