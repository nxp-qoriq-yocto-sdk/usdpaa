CROSS_COMPILE=/opt/freescale/usr/local/gcc-4.3.74-eglibc-2.8.74-6/powerpc-linux-gnu/bin/powerpc-linux-gnu-
C_TARG_FLAGS=-mcpu=e500mc -msoft-float -D_GCCPORT_ -D__POWERPC__ \
	-D__PPC_EABI__ -mmultiple -mno-altivec -pthread
C_MY_FLAGS=-Iinclude -Wall -Werror -O2 -ggdb3
CC=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar

LIB_SRC=qman/qman_high.c qman/qman_low.c qman/qman_fqalloc.c \
	qman/qman_utility.c qman/qman_driver.c \
	bman/bman_high.c bman/bman_low.c bman/bman_driver.c

# Simplicity, meet large stick. Large stick, simplicity.
default: rebuild

rebuild: clean build_lib \
	build_qman_test_high \
	build_bman_test_high \
	build_speed \
	build_user_example

clean:
	rm -f objs/*.o *.a

build_lib:
	@for i in $(LIB_SRC); do \
		$(CC) -c $(C_TARG_FLAGS) $(C_MY_FLAGS) $$i && mv *.o objs/ || \
			exit 1; \
		echo "[CC] $$i"; \
	done
	@$(AR) rcs libusd.a objs/*.o
	@echo "[AR] libusd.a"

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

build_user_example:
	@$(CC) -c $(C_TARG_FLAGS) $(C_MY_FLAGS) apps/user_example.c && \
		mv *.o objs/ || exit 1
	@echo "[CC] user_example"
	@$(CC) $(C_TARG_FLAGS) -o user_example \
		objs/user_example.o \
		objs/qman_test_high.o \
		objs/bman_test_high.o \
		objs/speed.o \
		-L. -lusd -lpthread || exit 1
	@echo "[LINK] user_example"

