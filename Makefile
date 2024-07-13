all: libnss_k9.so.2

libnss_k9.so.2:
	gcc -g -fPIC -shared -o libnss_k9.so.2 -Wl,-soname,libnss_k9.so.2 k9.c strlcpy.c passwd.c passwd-locked.c group.c group-locked.c shadow.c shadow-locked.c config.c -lcurl -lyaml -ljson-c -lpthread

clean:
	rm -f libnss_k9.so.2

