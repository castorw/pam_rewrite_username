.DEFAULT_GOAL=build

build:
	gcc -fPIC -shared -lpam -fno-stack-protector -o pam_rewrite_username.so pam_rewrite_username.c

install:
	install -m 0644 pam_rewrite_username.so $(prefix)/lib/security
