# Kattis has -O2 -std=gnu11
CFLAGS := -Wall -g -O2 -std=gnu11

MULT_COEFFS = 2 3 9 11 13 14
MULT_INCS = $(patsubst %, mult%.inc, $(MULT_COEFFS))

SBOX_INCS = sbox_forward.inc sbox_backward.inc

INCS = $(MULT_INCS) $(SBOX_INCS)

ifneq ($(kattis),yes)
	# If not for kattis, compile in decryption
	# and flexible main
	CFLAGS += -DDECRYPT -DFLEXIBLE
endif

# Off by default
ENABLE_DEBUG=no

ifeq ($(ENABLE_DEBUG),yes)
	CFLAGS+=-DDEBUG
endif

exec: main.o aes.o
	gcc $(CFLAGS) -o $@ $^

libappcrypaes.a: aes.o
	ar rcs $@ $^

main.o: main.c
	gcc -c $(CFLAGS) -o $@ $^

aes.o: aes.c $(INCS)
	gcc -c $(CFLAGS) -o $@ $<

galois-mult: galois_mult.c
	gcc $(CFLAGS) -o $@ $^

gen-sbox: gen_sbox.c
	gcc $(CFLAGS) -o $@ $^

mult%.inc: galois-mult
	./$< $* >$@

sbox_%.inc: gen-sbox
	./$< $* >$@

clean:
	rm -f aes.o main.o exec libappcrypaes.a gen-sbox galois-mult $(INCS)
