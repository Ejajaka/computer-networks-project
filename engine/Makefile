# compiler and target
CLANG ?= clang
BPF_TARGET ?= bpf
# build flags for eBPF
BPF_CFLAGS := -O2 -g -Wall -Wno-unused-value -Wno-pointer-sign
BPF_CFLAGS += -target bpf
BPF_CFLAGS += -D__TARGET_ARCH_x86
BPF_CFLAGS += -I/usr/include/x86_64-linux-gnu
BPF_CFLAGS += -I/usr/include

# filter sources -> object files
SRCS_KERN := udp_filter_kern.c syn_filter_kern.c ddos_filter_kern.c
OBJS_KERN := $(SRCS_KERN:.c=.o)

all: $(OBJS_KERN)

# compile each .c to .o
$(OBJS_KERN): %.o: %.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS_KERN)

.PHONY: all clean
