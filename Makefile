SHELL := /bin/bash
KEYTYPE="ed25519-sk"
#KEYTYPE="ecdsa-sk"
DEVICE=$(shell fido2-token -L | cut -d: -f1-2)
APPLICATION=ssh:sign
METADATA=https://raw.githubusercontent.com/Yubico/java-webauthn-server/7cc725d61f4dc376db81bfd84a31c6b33931056d/webauthn-server-demo/src/main/resources/metadata.json

ID_FIDO_GEN_CE_AAGUID=1.3.6.1.4.1.45724.1.1.4

# Given a signed file, a pubkey, and an attestation
# Find out
# - if the file was signed using the pubkey
# - if the corresponding private key was backed by a YubiKey
all: setup verify-sig verify-certificate verify-attestation verify-key aaguid rpid

# generate the files under investigation
setup: setpin sk.pub file.sig attestation.bin

###
### generate key and attestation
###

# Resident keys require that a PIN be set on the authenticator
setpin:
	$(shell fido2-token -I "${DEVICE}" | grep noclientPin && ykman fido access change-pin --new-pin ${PIN})

# generate FIDO authenticator-backed keys
# key handle part stored in the private key file on disk
# save attestation data

sk sk.pub attestation.bin: challengefile
	ssh-keygen -t ${KEYTYPE} -f ./sk -N "" -C signer@example.org -O write-attestation=attestation.bin -O application="${APPLICATION}" -O challenge=challengefile -O no-touch-required

# some random challenge data to hash
challengefile:
	openssl rand -out challengefile 128

###
### parse attestation
###

attestation.yaml: attestation.bin
	@cat attestation.bin | php attestation.php > attestation.yaml

attestation-signature.bin: attestation.yaml
	@cat attestation.yaml | yq .attestation.signature | xxd -r -p > attestation-signature.bin

authData.cbor: attestation.yaml
	@cat attestation.yaml | yq .attestation.authData | xxd -r -p > authData.cbor

authData.bin: authData.cbor
	@cat authData.cbor | cbor2json | jq '.data[]' | perl -ne 'printf("%02x",$$_)' | xxd -r -p > authData.bin

authData.yaml: authData.bin
	@cat authData.bin | php authData.php > authData.yaml

###
### verify attestation certificate using the CA certificate
###

# extract the attestation certificate from the attestation data
attestation-certificate.pem: attestation.yaml
	@cat attestation.yaml | yq .attestation.certificate | xxd -r -p | openssl x509 -inform der -out attestation-certificate.pem

# retrieve the issuer certificate (specific for YubiKeys)
yubico-u2f-ca-certs.txt:
	@wget -q https://developers.yubico.com/U2F/yubico-u2f-ca-certs.txt

# verify the attestation certificate is issued by Yubico
verify-certificate: yubico-u2f-ca-certs.txt attestation-certificate.pem 
	openssl verify -CAfile yubico-u2f-ca-certs.txt attestation-certificate.pem 

# verify the certificate's AAGUID matches the authenticator data, and determine the yubikey model from metadata
aaguid: attestation-certificate.pem authData.yaml metadata.json
	@openssl asn1parse -in attestation-certificate.pem | grep ${ID_FIDO_GEN_CE_AAGUID} -A1 | tail -1 | grep -o '\[HEX DUMP\]:.*' | cut -d: -f2 | xxd -r -p | openssl asn1parse -inform der | grep -o '\[HEX DUMP\]:.*' | cut -d: -f2 | tr A-Z a-z | diff - <(cat authData.yaml | yq .authdata.attestedCredentialData.aaguid) && /bin/echo -n "OK: AAGUID matches "
	@jq --arg aaguid $$(cat authData.yaml | yq .authdata.attestedCredentialData.aaguid) -f aaguid.jq metadata.json

metadata.json:
	@wget -q ${METADATA}

rpid:
	@diff <(/bin/echo -n ${APPLICATION} | openssl sha256) <(cat authData.yaml | yq .authdata.rpIdHash) && echo OK: RP ID ${APPLICATION} matches

###
### verify the signature using the attestation certificate
###

verify-attestation: attestation-pubkey.pem attestation-signature.bin signeddata
	openssl dgst -sha256 -verify attestation-pubkey.pem -signature attestation-signature.bin signeddata

attestation-pubkey.pem: attestation-certificate.pem
	openssl x509 -in attestation-certificate.pem -noout -pubkey > attestation-pubkey.pem

signeddata: authData.bin clientdatahash
	@cat authData.bin clientdatahash > signeddata

clientdatahash: challengefile
	@cat challengefile | openssl sha256 -binary > clientdatahash

### verify the attested key matches the public key

sk.yaml: sk.pub
ifeq ($(KEYTYPE),"ecdsa-sk")
	@cat sk.pub | cut -d' ' -f2 | base64 -d | php ecdsa_sk.php > sk.yaml
else
	@cat sk.pub | cut -d' ' -f2 | base64 -d | php ed25519_sk.php > sk.yaml
endif

verify-key: authData.yaml sk.yaml
ifeq ($(KEYTYPE),"ecdsa-sk")
	@diff <(cat authData.yaml | yq '.authdata.attestedCredentialData.credentialPublicKey|("04" + .x + .y)') <(cat sk.yaml | yq .ecdsa_sk.q) && echo OK: pubkey matches
else
	@diff <(cat authData.yaml | yq '.authdata.attestedCredentialData.credentialPublicKey.x') <(cat sk.yaml | yq .ed25519_sk.pubkey) && echo OK: pubkey matches
endif

###
### SIGNING
###

verify-sig: file.sig allowed_signers
	ssh-keygen -Y verify -n file -f ./allowed_signers -s file.sig -I signer@example.org < file

file:
	echo Hello World > file

file.sig: file
	ssh-keygen -Y sign -n file -f ./sk ./file

allowed_signers: sk.pub
	(/bin/echo -n "signer@example.org "; cat ./sk.pub) > allowed_signers


### MISC

clean:
	-rm sk sk.pub attestation.bin attestation-certificate.pem attestation-pubkey.pem authData.cbor authData.bin clientdatahash file file.sig yubico-u2f-ca-certs.txt allowed_signers signeddata attestation-signature.bin
	-rm challengefile attestation.yaml authData.yaml sk.yaml metadata.json
