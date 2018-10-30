## Introduce

SM2/SM3 are included from [OpenSSL 1.1.1](https://www.openssl.org/blog/blog/2018/09/11/release111/), but the php internal [OpenSSL module](http://php.net/manual/en/book.openssl.php) needs some upgrades to apply the benefits.

This php extension exposes SM2/SM3 to php and provides more easy API then php OpenSSL does.

## Install

```bash
git clone https://github.com/hsiaosiyuan0/php-sm.git
cd repo
phpize
./configure --enable-sm
make
make test
make install
```

## API

```ts
// generates pkey resource from hex encoded private key
sm2_pkey_from_pri(pri: hexString) => resource;

// generates pkey resource from hex encoded public key
sm2_pkey_from_pub(pub: hexString) => resource;

type Mode = "uncompress" | "compress" | "mix";

// extracts public key from pkey resource
sm2_pkey_get_public(pkey: resource, mode: Mode = "uncompress", hex: bool = false) => hexString | binaryString;

// extracts private key from pkey resource
sm2_pkey_get_private(pkey: resource, hex: bool = false) => hexString;

// sign data with pkey resource and produces hex encoded signature
sm2_sign(data: string, pkey: resource) => hexString | false;

// verify signature with pkey resource, 1 is correct, 0 if it is incorrect, and -1 on error.
sm2_verify(data: string, sig: string, pkey: resource) => 1|0|-1;

// sign data with pem encoded private key
sm2_sign_with_pem(data: string, pem: string) => string | false;

// verify signature with pem encoded public key, 1 is correct, 0 if it is incorrect, and -1 on error.
sm2_verify_with_pem(data: string, sig: string, pem: string) => 1|0|-1;
```
