#!/usr/bin/env php
<?php

include("common.php");

# The format of a sk-ecdsa-sha2-nistp256@openssh.com public key is:

#	string		"sk-ecdsa-sha2-nistp256@openssh.com"
#	string		curve name
#	ec_point	Q
#	string		application (user-specified, but typically "ssh:")


$s = file_get_contents('php://stdin');

echo "ecdsa_sk:\n";

[$t,$l,$v] = tlv($s);
assert( bin2hex($t) === "0000" );
assert($v === "sk-ecdsa-sha2-nistp256@openssh.com");
echo "  format: $v\n";

[$t,$l,$v] = tlv($s);
assert( bin2hex($t) === "0000" );
echo "  curve: $v\n";

[$t,$l,$v] = tlv($s);
assert( bin2hex($t) === "0000" );
echo "  q: " . bin2hex($v) . "\n";

[$t,$l,$v] = tlv($s);
assert( bin2hex($t) === "0000" );
echo "  application: $v\n";

assert($s==="");
