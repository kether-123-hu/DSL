# =====================================================================
# Makefile —— 原生eBPF程序编译脚本
# =====================================================================
#
# 用于编译syscall_latency_native.bpf.c和syscall_latency_native.c
#
# 编译步骤：
# 1. 编译内核态BPF程序 -> syscall_latency_native.bpf.o
# 2. 生成skeleton头文件 -> syscall_latency_native.skel.h
# 3. 编译用户态加载器 -> syscall_latency_native
#
# =====================================================================

# 编译器设置
CLANG ?= clang
BPFTOOL ?= bpftool

# 目标文件
TARGET = syscall_latency_native
BPF_OBJ = syscall_latency_native.bpf.o
SKEL_H = syscall_latency_native.skel.h

# 编译选项
BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86
USER_CFLAGS = -O2 -g -Wall

# libbpf头文件路径（需要根据实际环境调整）
LIBBPF_INCLUDE ?= /usr/include
LIBBPF_LIB ?= /usr/lib

# =====================================================================
# 编译规则
# =====================================================================

.PHONY: all clean run

all: $(TARGET)

# 步骤1：编译内核态BPF程序
$(BPF_OBJ): syscall_latency_native.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# 步骤2：生成skeleton头文件
$(SKEL_H): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# 步骤3：编译用户态加载器
$(TARGET): syscall_latency_native.c $(SKEL_H)
	$(CLANG) $(USER_CFLAGS) -I$(LIBBPF_INCLUDE) -L$(LIBBPF_LIB) \
		$< -o $@ -lbpf -lelf

# =====================================================================
# 清理规则
# =====================================================================

clean:
	rm -f $(BPF_OBJ) $(SKEL_H) $(TARGET)

# =====================================================================
# 运行规则（需要root权限）
# =====================================================================

run: $(TARGET)
	sudo ./$(TARGET)