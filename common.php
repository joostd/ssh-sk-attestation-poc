<?php

// https://www.iana.org/assignments/cose/cose.xhtml#algorithms
define("ES256", -7);  // ECDSA      w/ SHA-256
define("EDDSA", -8);  // ECDSA      w/ SHA-256
define("PS256", -37); // RSASSA-PSS w/ SHA-256
// https://tools.ietf.org/html/rfc8152#section-7
define("KTY",  1); // key type
define("ALG",  3); // key usage restriction to this algorithm
define("CRV", -1); // curve to be used with the key
define("X",   -2); // y-coordinate for the EC point.  
define("Y",   -3); // y-coordinate for the EC point.  
// https://tools.ietf.org/html/rfc8152#section-13 (table 21)
define("OKP", 1); // Octet Key Pair
define("EC2", 2); // Elliptic Curve Keys w/ x- and y-coordinate pair 
// https://tools.ietf.org/html/rfc8152#section-13.1 (table 22)
define("P256", 1); // NIST P-256 also known as secp256r1 
define("ED25519", 6); // NIST P-256 also known as secp256r1 

function shiftn(string &$s, $n) {
    $a = substr($s,0,$n);
    $s = substr_replace( $s, '', 0, $n);
    return $a;
  }

function tlv(string &$s) {
	$t = shiftn($s,2);
	#error_log( bin2hex($t)."," );
	$l = shiftn($s,2);
	#error_log( bin2hex($l)."," );
	$len = unpack("n",$l)[1]; // unsigned int (always 16 bit, big endian byte order)
	$v = shiftn($s,$len);
	#error_log( bin2hex($v)."\n" );
	return [$t,$l,$v];
}
