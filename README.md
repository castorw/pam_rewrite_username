# pam_rewrite_username
Simple PAM plugin to add prefix and/or suffix to username while authenticating.

## Building
Required: make gcc libpam-devel
```bash
make
make install
```

## Usage
```
auth  requisite /lib/security/pam_rewrite_username.so prefix=xxx. suffix=@yyy
```
The above example will change the user from "user" to xxx.user@yyy.

```
auth  requisite /lib/security/pam_rewrite_username.so prefix=vpn.
```
The above example will change the user from "peter" to vpn.peter
