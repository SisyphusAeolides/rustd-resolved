CC ?= cc
CFLAGS ?= -O2 -g -fPIC -std=c17 -Wall -Wextra -Werror -Wpedantic -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3
LDFLAGS_SO ?= -shared -Wl,-soname,libnss_rustd_dns.so.2 -Wl,--version-script=nss-rustd-dns.sym -Wl,-z,relro,-z,now
PREFIX ?= /usr
LIBDIR ?= $(PREFIX)/lib

OBJS = nss_resolve.o nss_resolve_shm.o nss_dns_stub.o nss_varlink.o
TEST_OBJS = test_nss.o test_shm.o

.PHONY: all check clean install

all: libnss_rustd_dns.so.2

libnss_rustd_dns.so.2: $(OBJS) nss-rustd-dns.sym
	$(CC) $(LDFLAGS_SO) -o $@ $(OBJS)

test_nss: test_nss.o $(OBJS)
	$(CC) -o $@ test_nss.o $(OBJS)

test_shm: test_shm.o nss_resolve_shm.o
	$(CC) -o $@ test_shm.o nss_resolve_shm.o

check: all test_nss test_shm
	./test_shm
	bash run-tests.sh

%.o: %.c nss_resolve_shm.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TEST_OBJS) libnss_rustd_dns.so.2 test_nss test_shm

install: all
	install -Dm0755 libnss_rustd_dns.so.2 $(DESTDIR)$(LIBDIR)/libnss_rustd_dns.so.2
