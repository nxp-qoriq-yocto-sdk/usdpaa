CROSS_COMPILE ?= /opt/freescale/usr/local/gcc-4.4.78-eglibc-2.10.78/powerpc-linux-gnu/bin/powerpc-linux-gnu-

CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar

C_TARG_FLAGS=-mcpu=e500mc -msoft-float -D_GCCPORT_ -D__POWERPC__ \
	-D__PPC_EABI__ -mmultiple -mno-altivec -pthread
C_MY_FLAGS=-Iinclude -Wall -Werror -O2 -ggdb3

LIB_SRC=qman/qman_high.c qman/qman_low.c qman/qman_fqalloc.c qman/qman_utility.c	\
	qman/qman_driver.c								\
	bman/bman_high.c bman/bman_low.c bman/bman_driver.c				\
	shmem/shmem.c shmem/shmem_alloc.c						\
	of/of.c										\
	fman/fman.c

# Simplicity, meet large stick. Large stick, simplicity.
default: rebuild

rebuild: clean build_lib \
	build_common \
	build_qman_test_high \
	build_bman_test_high \
	build_speed \
	build_blastman \
	build_user_example \
	build_poc

.PHONY: clean
clean:
	$(RM) objs/*.o *.a

build_lib:
	@for i in $(LIB_SRC); do \
		$(CC) -c $(C_TARG_FLAGS) $(C_MY_FLAGS) $$i && mv *.o objs/ || \
			exit 1; \
		echo "[CC] $$i"; \
	done
	@$(AR) rcs libusd.a objs/*.o
	@echo "[AR] libusd.a"

build_common:
	@$(CC) -c $(C_TARG_FLAGS) $(C_MY_FLAGS) apps/common.c && \
		mv *.o objs/ || exit 1
	@echo "[CC] common"

build_qman_test_high:
	@$(CC) -c $(C_TARG_FLAGS) $(C_MY_FLAGS) apps/qman_test_high.c && \
		mv *.o objs/ || exit 1
	@echo "[CC] qman_test_high"

build_bman_test_high:
	@$(CC) -c $(C_TARG_FLAGS) $(C_MY_FLAGS) apps/bman_test_high.c && \
		mv *.o objs/ || exit 1
	@echo "[CC] bman_test_high"

build_speed:
	@$(CC) -c $(C_TARG_FLAGS) $(C_MY_FLAGS) apps/speed.c && \
		mv *.o objs/ || exit 1
	@echo "[CC] speed"

build_blastman:
	@$(CC) -c $(C_TARG_FLAGS) $(C_MY_FLAGS) apps/blastman.c && \
		mv *.o objs/ || exit 1
	@echo "[CC] blastman"

build_user_example:
	@$(CC) -c $(C_TARG_FLAGS) $(C_MY_FLAGS) apps/user_example.c && \
		mv *.o objs/ || exit 1
	@echo "[CC] user_example"
	@$(CC) $(C_TARG_FLAGS) -o user_example \
		objs/user_example.o \
		objs/qman_test_high.o \
		objs/bman_test_high.o \
		objs/speed.o \
		objs/blastman.o \
		objs/common.o \
		-L. -lusd -lpthread || exit 1
	@echo "[LINK] user_example"

build_poc:
	@$(CC) -c $(C_TARG_FLAGS) $(C_MY_FLAGS) apps/poc.c && \
		mv *.o objs/ || exit 1
	@echo "[CC] poc"
	@$(CC) $(C_TARG_FLAGS) -o poc \
		objs/poc.o \
		objs/common.o \
		-L. -lusd -lpthread || exit 1
	@echo "[LINK] poc"

install:
	install -d $(DESTDIR)$(PREFIX)/bin
	install user_example poc of/of.sh $(DESTDIR)$(PREFIX)/bin
	install apps/us_*.xml $(DESTDIR)
