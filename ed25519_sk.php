#!/usr/bin/env php
<?php

include("common.php");

# The format of a sk-ssh-ed25519@openssh.com public key is:
#	string		"sk-ssh-ed25519@openssh.com"
#	string		public key
#	string		application (user-specified, but typically "ssh:")

$s = file_get_contents('php://stdin');

echo "ed25519_sk:\n";

[$t,$l,$v] = tlv($s);
assert( bin2hex($t) === "0000" );
assert($v === "sk-ssh-ed25519@openssh.com");
echo "  format: $v\n";

[$t,$l,$v] = tlv($s);
assert( bin2hex($t) === "0000" );
echo "  pubkey: " . bin2hex($v) . "\n";

[$t,$l,$v] = tlv($s);
assert( bin2hex($t) === "0000" );
echo "  application: $v\n";

assert($s==="");
