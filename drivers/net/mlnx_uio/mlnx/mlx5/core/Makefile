ccflags-y += $(MLNX_CFLAGS)

obj-$(CONFIG_MLX5_CORE)		+= mlx5_core.o

mlx5_core-y :=	main.o cmd.o debugfs.o fw.o eq.o uar.o pagealloc.o \
		health.o mcg.o cq.o srq.o alloc.o qp.o port.o mr.o pd.o   \
		mad.o wq.o flow_table.o vport.o transobj.o en_main.o \
		en_flow_table.o en_ethtool.o en_tx.o en_rx.o en_txrx.o \
		sriov.o params.o en_debugfs.o
