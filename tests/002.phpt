--TEST--
sm2_pkey_from_pri and sm2_pkey_from_pub tests
--SKIPIF--
<?php if (!extension_loaded("sm")) print "skip"; ?>
--FILE--
<?php
$pk = sm2_pkey_from_pri("ab80a7ad086249c01e65c4d9bb6ce18de259dcfc218cd49f2455c539e9112ca3");
$priHex = sm2_pkey_get_private($pk, true);
var_dump("ab80a7ad086249c01e65c4d9bb6ce18de259dcfc218cd49f2455c539e9112ca3" === $priHex);

$pubHex = sm2_pkey_get_public($pk, "compress", true);
var_dump("031220580679fda524f575ac48b39b9f74cb0a97993df4fac5798b04c702d07a39" === $pubHex);

$pk = sm2_pkey_from_pub("031220580679fda524f575ac48b39b9f74cb0a97993df4fac5798b04c702d07a39");
$pubHex = sm2_pkey_get_public($pk, "compress", true);
var_dump("031220580679fda524f575ac48b39b9f74cb0a97993df4fac5798b04c702d07a39" === $pubHex);

--EXPECT--
bool(true)
bool(true)
bool(true)
