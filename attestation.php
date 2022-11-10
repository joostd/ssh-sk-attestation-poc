<?php

include("common.php");

# input must be an SSH security key attestation:

# Attestation format is:
# string		"ssh-sk-attest-v01"
# string		attestation certificate
# string		enrollment signature
# string		authenticator data (CBOR encoded)
# uint32		reserved flags
# string		reserved string


$s = file_get_contents('php://stdin');

echo "attestation:\n";

[$t,$l,$v] = tlv($s);
assert( bin2hex($t) === "0000" );
assert($v === "ssh-sk-attest-v01");
echo "  format: " . bin2hex($v) . "\n";

[$t,$l,$v] = tlv($s);
assert( bin2hex($t) === "0000" );
echo "  certificate: " . bin2hex($v) . "\n";

[$t,$l,$v] = tlv($s);
assert( bin2hex($t) === "0000" );
echo "  signature: " . bin2hex($v) . "\n";

[$t,$l,$v] = tlv($s);
assert( bin2hex($t) === "0000" );
echo "  authData: " . bin2hex($v) . "\n";

# reserved flags
[$t,$l,$v] = tlv($s);
assert( bin2hex($t) === "0000" );

# reserved string
[$t,$l,$v] = tlv($s);
assert( bin2hex($t) === "0000" );

assert($s==="");
