<?php

include("vendor/autoload.php");
include("common.php");

use CBOR\CBOREncoder;

# input must be binary data
$s = file_get_contents('php://stdin');

# See https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data

echo "authdata:\n";

# name		length	descrription

# rpIdHash	32	SHA-256 hash of the RP ID the credential is scoped to.

    $rpIdHash = shiftn($s,32);
    echo "  rpIdHash: " . bin2hex($rpIdHash) . "\n";

# flags		1	Flags ED AT -- -- -- UV -- UP

    echo "  flags:\n";
    $flags = shiftn($s,1);
    echo "    raw: " . bin2hex($flags) . "\n";
    $flags = ord($flags);
    $up = ($flags & 0x01); // user presence
    $uv = ($flags & 0x04); // user verification
    $at = ($flags & 0x40); // attestation
    $ed = ($flags & 0x80); // extensions
    #assert( $up ); // user presence: UP == 1
    echo "    ed: " . bin2hex(chr($ed)) . "\n";
    echo "    at: " . bin2hex(chr($at)) . "\n";
    echo "    uv: " . bin2hex(chr($uv)) . "\n";
    echo "    up: " . bin2hex(chr($up)) . "\n";
    #echo "  flags: ED=$ed AT=$at UV=$uv UP=$up\n";

# signCount	4	Signature counter, 32-bit unsigned big-endian integer.

    $signCount = shiftn($s,4);
    #echo "  signCount: " . bin2hex($signCount) . "\n";
    $signCount = unpack("N",$signCount)[1]; // unsigned long (always 32 bit, big endian byte order)
    echo "  signCount: " . ($signCount) . "\n";

# attestedCredentialData	n	attested credential data. length depends on the length of the credential ID and credential public key being attested.

    assert(strlen($s) > 0); // for registration, attestedCredentialData must be present
    $attestedCredentialData = $s; // assuming no extensions
    echo "  attestedCredentialData:\n";
    echo "    raw: " . bin2hex($attestedCredentialData) . "\n";

# attested credential data, see https://www.w3.org/TR/webauthn-2/#sctn-attested-credential-data

# aaguid	16	The AAGUID of the authenticator.

    $aaguid = shiftn($s,16); // Authenticator Attestation Globally Unique ID (AAGUID) 
    # match against https://support.yubico.com/hc/en-us/articles/360016648959-YubiKey-Hardware-FIDO2-AAGUIDs
    // TODO: use aaguid to look up a metadata statement in the FIDO Metadata Service
    echo "    aaguid: " . bin2hex($aaguid) . "\n"; // all 0s for attestation "none"

# credentialIdLength	2	Byte length L of Credential ID, 16-bit unsigned big-endian integer.
# credentialId		L	Credential ID

    $credentialIdLength = shiftn($s,2);
    #echo "    credentialIdLength: " . bin2hex($credentialIdLength) . "\n";
    $length = unpack("n",$credentialIdLength)[1]; // unsigned short (always 16 bit, big endian byte order)
    #print("length=$length\n");
    $credentialId = shiftn($s,$length);
    echo "    credentialId: " . bin2hex($credentialId) . "\n";

# credentialPublicKey	variable	The credential public key encoded in COSE_Key format

    echo "    credentialPublicKey:\n";
    echo "      raw: " . bin2hex($s) . "\n"; // if no extensions
    $credentialPublicKey = \CBOR\CBOREncoder::decode($s); // note that credentialPublicKey may be followed by extensions

    switch($credentialPublicKey[KTY]) {
	case EC2:
    	    assert($credentialPublicKey[KTY] == EC2);
    	    assert($credentialPublicKey[ALG] == ES256);
    	    assert($credentialPublicKey[CRV] == P256);
            $x = bin2hex($credentialPublicKey[X]->get_byte_string());
            $y = bin2hex($credentialPublicKey[Y]->get_byte_string());
            echo "      x: $x\n";
            echo "      y: $y\n";
	    break;
	case OKP:
            assert($credentialPublicKey[KTY] == OKP);
            assert($credentialPublicKey[ALG] == EDDSA);
            assert($credentialPublicKey[CRV] == ED25519);
            $x = bin2hex($credentialPublicKey[X]->get_byte_string());
            echo "      x: $x\n";
	    break;
        default:
	    var_dump($credentialPublicKey);
	    exit(0);
    }

# extensions			n	Extension-defined authenticator data

    $extensions = null;
    if (strlen($s) > 0) { 
        echo "  extensions:\n";
        echo "    raw: " . bin2hex($s) . "\n";
        $extensions = \CBOR\CBOREncoder::decode($s);
    }
    if( isset($extensions['credProtect']) ) {
        echo "    credProtect: ";
        switch($extensions['credProtect']) {
            case 0x01:
                echo "userVerificationOptional\n";
		break;
            case 0x02:
                echo "userVerificationOptionalWithCredentialIDList\n";
		break;
        }
    } else
        error_log( print_r( $extensions, true )."\n");
