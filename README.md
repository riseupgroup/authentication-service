# Authentication-Service

**used for RiseUpGroup's auth-server**

## Keypair generation

Generate a private key with the following command. If you like, you may change the key length. The following command generates a 4096-bit key:

```sh
openssl genrsa -out private.pem 4096
```

To extract the public key from the private key, run the following command:

```sh
openssl rsa -in private.pem -pubout -out public.pem
```
