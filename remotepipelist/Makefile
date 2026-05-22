BOFNAME := remotepipelist
CC_x64 := x86_64-w64-mingw32-gcc -nostdlib
BOFLINK := boflink

CFLAGS := -Os -c -DBOF -fno-builtin -D__USE_MINGW_ANSI_STDIO=0

all:
	@mkdir -p dist build
	$(CC_x64) $(CFLAGS) -o build/entry.x64.o entry.c
	$(BOFLINK) -L/usr/x86_64-w64-mingw32/lib build/entry.x64.o --entry=go \
		-lkernel32 -lmsvcrt -lws2_32 -lsecur32 -lbcrypt -o dist/$(BOFNAME).x64.o

clean:
	rm -rf dist build
