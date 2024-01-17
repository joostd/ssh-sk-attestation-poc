#!/usr/bin/env php
<?php

include("common.php");

# https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key<F4>ee 

# The key consists of a header, a list of public keys, and
# an encrypted list of matching private keys.

define("AUTH_MAGIC", "openssh-key-v1");

#	byte[]	AUTH_MAGIC
#	string	ciphername
#	string	kdfname
#	string	kdfoptions
#	uint32	number of keys N
#	string	publickey1
#	string	publickey2
#	...
#	string	publickeyN
#	string	encrypted, padded list of private keys



# The format of a sk-ecdsa-sha2-nistp256@openssh.com public key is:

#	string		"sk-ecdsa-sha2-nistp256@openssh.com"
#	string		curve name
#	ec_point	Q
#	string		application (user-specified, but typically "ssh:")


$s = file_get_contents('php://stdin');

$magic = shiftn($s,strlen(AUTH_MAGIC));
assert( $magic === AUTH_MAGIC);
echo "openssh_key_v1:\n";
$null = shiftn($s,1);
assert($null='\0');

[$t,$l,$v] = tlv($s);
assert( $t === "\0\0" );
assert( $v === "none" );
echo "  cipher: $v\n";

[$t,$l,$v] = tlv($s);
assert( $t === "\0\0" );
assert( $v === "none" );
echo "  kdf: $v\n";

[$t,$l,$v] = tlv($s);
assert( $t === "\0\0" );
assert( $v === "" );
echo "  options: $v\n";

[$t,$l,$v] = tlv($s);
print(bin2hex($t)."\n");
print(bin2hex($l)."\n");
print(bin2hex($v)."\n");
assert( bin2hex($t) === "0000" );
assert( $v === "\0" );
$v = unpack("C",$v)[1]; // unsigned char
echo "  numkeys: $v\n";

echo "";

[$t,$l,$v] = tlv($s);
print(bin2hex($t)."\n");
print(bin2hex($l)."\n");
print(bin2hex($v)."\n");
assert( bin2hex($t) === "0000" );
#assert( $v) === "none" ;

assert($s==="");
