# SSH FIDO security key attestation Proof of Concept

Some tools required. To install:

    brew install npm php composer jq yq ykman libfido2 wget
    npm install -g cbor-cli
    composer install

Insert a FIDO security key and type

    make

What happens next is described below.

# Generating keys and attestation

Generate a random challenge file to use with the attestation.

    openssl rand 128 -out challengefile

Generate SSH keys backed by a security key.
Save the attestation file

    ssh-keygen -t "ed25519-sk" -f ./sk -N "" -C signer@example.org -O write-attestation=attestation.bin -O application="ssh:sign" -O challenge=challengefile -O no-touch-required
    Generating public/private ed25519-sk key pair.
    You may need to touch your authenticator to authorize key generation.
    Enter PIN for authenticator: 
    You may need to touch your authenticator again to authorize key generation.
    Your identification has been saved in ./sk
    Your public key has been saved in ./sk.pub
    The key fingerprint is:
    SHA256:ubSNhUTSavW5TZdlKB4i2puW/JDOhbI4SMcVyl9fyqM signer@example.org
    The key's randomart image is:
    +[ED25519-SK 256]-+
    |      ...      . |
    |      .o+ . o . o|
    |   . . *.o + o + |
    |    o =.ooo + o  |
    |   . + oSO.* .   |
    |  . o o.X*B .    |
    | . o . *+=..     |
    |  . o . E .      |
    |     .           |
    +----[SHA256]-----+
    Your FIDO attestation certificate has been saved in attestation.bin

# Sign something

Generate a file and sign it using your key

    echo Hello World > file
    ssh-keygen -Y sign -n file -f ./sk ./file
    Signing file ./file
    Write signature to ./file.sig

To verify the signature, generate an `allowed_signers` file with your public SSH key

    (/bin/echo -n "signer@example.org "; cat ./sk.pub) > allowed_signers

# Verify the signature

    ssh-keygen -Y verify -n file -f ./allowed_signers -s file.sig -I signer@example.org < file
    Good "file" signature for signer@example.org with ED25519-SK key SHA256:ubSNhUTSavW5TZdlKB4i2puW/JDOhbI4SMcVyl9fyqM

# Attestation

The question now is: can we prove that the key that signed this file was backed by a FIDO security key?

First verify that the attestation certificate validates against the Root CA (in this case Yubico)

    openssl verify -CAfile yubico-u2f-ca-certs.txt attestation-certificate.pem 
    attestation-certificate.pem: OK

Then verify that the attestation signature is valid

    openssl x509 -in attestation-certificate.pem -noout -pubkey > attestation-pubkey.pem
    openssl dgst -sha256 -verify attestation-pubkey.pem -signature attestation-signature.bin signeddata
    Verified OK

Lastly, check that the public key used to sign the file matches the public key in the attestation

    OK: pubkey matches

While we're at it, lets also check that the AAGUID in the attestation matches the AAGUID in the attestation certificate

    OK: AAGUID matches "YubiKey 5Ci"

And check that the RP ID Hash we used when generating our keys matches the attestation

    OK: RP ID ssh:sign matches
