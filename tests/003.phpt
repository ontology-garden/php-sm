--TEST--
sm2_sign and sm2_verify tests
--SKIPIF--
<?php if (!extension_loaded("sm")) print "skip"; ?>
--FILE--
<?php
$pub_pem = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEEiBYBnn9pST1daxIs5ufdMsKl5k9
9PrFeYsExwLQejlicjbjR/jDMVWWvUdpz3K8zDbqQi2gh6MbQQuKK3BZiQ==
-----END PUBLIC KEY-----";

$javaSig = "bc1d431f932afb7b809627f051c1b5c10ee22e470aea4623c3281231dd513779ca1171f4f3bbf414f089e8c963f715b3376007008206a2b9ebb252dd6883dbce";

$ok = sm2_verify_with_pem("test", $javaSig, $pub_pem);
var_dump($ok);

$pk = sm2_pkey_from_pri("ab80a7ad086249c01e65c4d9bb6ce18de259dcfc218cd49f2455c539e9112ca3");
$sig = sm2_sign("test", $pk);

$pk = sm2_pkey_from_pub("031220580679fda524f575ac48b39b9f74cb0a97993df4fac5798b04c702d07a39");
$ok = sm2_verify("test", $sig, $pk);
var_dump($ok);
--EXPECT--
int(1)
int(1)
