# ANLAB customized DPDK
~~~~~~~~~~~~~{.sh}
#configure dpdk with
make config T=anlab
~~~~~~~~~~~~~

## Pure UIO based Mellanox ConnectX-3 driver (mlx4_uio)
DPDK's default mlx4 dirver is based on the kernel driver and ib_verb.
This is pure uio-based poll-mode driver for mlx4 driver.

###Requirements
Mellanox ConnectX-3 devices require scratch memory to be initialized.
However, DPDK's memzone is always re-initialized on application restart.
Thus, we need a persistent memory which is not volatile during several executions.
This functionality is based on hugepages and shared memory.
We need 2MB pages (other sizes are not supported yet).
Enable it before starting DPDK applications.
The following configurations are ours.
You may use other equivalent configurations on your own.

1. /etc/fstab 
~~~~~~~~~~~~~{.fstab}
hugetlbfs /mnt/hugepages hugetlbfs mode=1770,gid=1001 0 0
#make sure that you have empty /mnt/hugepages directory
#or your boot will fail
~~~~~~~~~~~~~

1. /etc/sysctl.conf
~~~~~~~~~~~~~{.conf}
vm.hugetlb_shm_group = 1001
vm.nr_hugepages = 3072
kernel.shmmax = 8589934592
kernel.shmall = 33554432
~~~~~~~~~~~~~

Our driver supports scatter-gather functionality just like other DPDK drivers.
VLAN support is implemented based on the kernel driver, but not tested.
Checksum offloading and timestamping are partially implemented.

##LICENSE
Our driver is based on Mellanox's kernel driver source code (BSD/GPLv2).
However, our kernel compatibility layer is based on Linux's source code (GPLv2).
All source files in drivers/net/mlnx_uio/include and drivers/net/mlnx_uio/kernel
are from Linux and slightly modified.
Currently, all source code in /drivers/net/mlnx_uio is distributed under GPLv2,
but we are planning to separate licenses or remove GPL dependencies.
