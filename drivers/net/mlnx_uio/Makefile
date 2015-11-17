#   BSD LICENSE
#
#   Copyright 2012-2015 6WIND S.A.
#   Copyright 2012 Mellanox.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions
#   are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#     * Neither the name of 6WIND S.A. nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

include $(RTE_SDK)/mk/rte.vars.mk

# Library name.
LIB = librte_pmd_mlnx_uio.a

#External driver sources
#-include $(SRCDIR)/driver_sources.mk

MLNX_SRC = $(wildcard $(SRCDIR)/mlnx/*.c) $(wildcard $(SRCDIR)/mlnx/*/*.c) $(wildcard $(SRCDIR)/mlnx/*/*/*.c)

$(SRCDIR)/driver_sources.mk: $(MLNX_SRC)
	echo $(MLNX_SRC)
	bash -c "cd $(SRCDIR); python3 prepare.py ."
	bash -c "cd $(SRCDIR); python3 convert.py mlnx"

VPATH+= $(SRCDIR)/kernel
CFLAGS+= -I$(SRCDIR)
CFLAGS+= -I$(SRCDIR)/include
CFLAGS+= -I$(SRCDIR)/mlnx/include


# Sources.
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += rbtree.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += radix-tree.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += bitmap.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += kcompat.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlx4_uio.c
# mlx4_en sources
#SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/en_tx.c
#SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/en_rx.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/en_tx_uio.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/en_rx_uio.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/en_port.c
#SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/en_netdev.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/en_main.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/en_selftest.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/en_sysfs.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/en_ethtool.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/en_dcb_nl.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/en_clock.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/en_cq.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/en_resources.c

# mlx4_core sources
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/main.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/port.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/qp.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/srq.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/eq.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/cq.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/sense.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/profile.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/pd.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/mr.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/fw_qos.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/catas.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/resource_tracker.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/intf.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/alloc.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/mcg.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/reset.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/icm.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/fw.c
SRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += mlnx/mlx4/cmd.c

# Dependencies.
DEPDIRS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += lib/librte_persistent
DEPDIRS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += lib/librte_ether
DEPDIRS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += lib/librte_mbuf
DEPDIRS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += lib/librte_eal
DEPDIRS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += lib/librte_mempool
DEPDIRS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += lib/librte_ring
DEPDIRS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += lib/librte_malloc

# Basic CFLAGS.
CFLAGS += -O3
CFLAGS += -std=gnu99 -Wall -Wextra
CFLAGS += -g
CFLAGS += -I.
CFLAGS += -D_XOPEN_SOURCE=600
#CFLAGS += $(WERROR_FLAGS)
CFLAGS += -Werror=implicit-function-declaration

# A few warnings cannot be avoided in external headers.
CFLAGS += -Wno-error=cast-qual

EXPORT_MAP := rte_pmd_mlnx_uio_version.map
LIBABIVER := 1

# DEBUG which is usually provided on the command-line may enable
# CONFIG_RTE_LIBRTE_MLNX_DEBUG.
ifeq ($(DEBUG),1)
CONFIG_RTE_LIBRTE_MLNX_UIO_DEBUG := y
endif

# User-defined CFLAGS.
ifeq ($(CONFIG_RTE_LIBRTE_MLNX_UIO_DEBUG),y)
CFLAGS += -UNDEBUG #-DPEDANTIC -pedantic
else
CFLAGS += -DNDEBUG -UPEDANTIC
endif

include $(RTE_SDK)/mk/rte.lib.mk

# Generate and clean-up MLNX_autoconf.h.

export CC CFLAGS CPPFLAGS EXTRA_CFLAGS EXTRA_CPPFLAGS
export AUTO_CONFIG_CFLAGS = -Wno-error
