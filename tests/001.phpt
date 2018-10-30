--TEST--
sm2_sign_with_pem and sm2_verify_with_pem tests
--SKIPIF--
<?php if (!extension_loaded("sm")) print "skip"; ?>
--FILE--
<?php
$pri_pem = "-----BEGIN EC PRIVATE KEY-----
MDECAQEEIKuAp60IYknAHmXE2bts4Y3iWdz8IYzUnyRVxTnpESyjoAoGCCqBHM9V
AYIt
-----END EC PRIVATE KEY-----";

$pub_pem = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEEiBYBnn9pST1daxIs5ufdMsKl5k9
9PrFeYsExwLQejlicjbjR/jDMVWWvUdpz3K8zDbqQi2gh6MbQQuKK3BZiQ==
-----END PUBLIC KEY-----";

$sig = sm2_sign_with_pem("test", $pri_pem);
$ok = sm2_verify_with_pem("test", $sig, $pub_pem);
var_dump($ok);

$javaSig = "bc1d431f932afb7b809627f051c1b5c10ee22e470aea4623c3281231dd513779ca1171f4f3bbf414f089e8c963f715b3376007008206a2b9ebb252dd6883dbce";
$ok = sm2_verify_with_pem("test", $sig, $pub_pem);
var_dump($ok);
--EXPECT--
int(1)
int(1)
