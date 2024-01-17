### STEP 1 : GENERATE KEY AND ATTESTATION

# generate a random challenge
openssl rand 128 > challengefile
# generate a key with attestation
ssh-keygen -t "ecdsa-sk" -f ./sk -N "" -C signer@example.org -O write-attestation=attestation.bin -O application="ssh:sign" -O challenge=challengefile # -O no-touch-required

### STEP 2 : SIGN A FILE AND VERIFY ITS SIGNATURE

# generate a file to be signed
echo Hello World > file
# sign the file
ssh-keygen -Y sign -n file -f ./sk ./file
# register the public key for verification
(/bin/echo -n "signer@example.org "; cat ./sk.pub) > allowed_signers
# verify the signature
ssh-keygen -Y verify -n file -f ./allowed_signers -s file.sig -I signer@example.org < file

### STEP 3 : OBTAIN METADATA FROM MDS

# download mds jwT
curl -Ls https://mds3.fidoalliance.org/ --output md.jwt
# download root ca cert
wget -q http://secure.globalsign.com/cacert/root-r3.crt
# convert to pem
openssl x509 -inform der -in root-r3.crt -out root-r3.pem
# extract intermediate ca certs
cat md.jwt | step crypto jwt inspect --insecure | jq -r '.header.x5c[1:][]' | while read pem; do echo $pem | base64 -d | openssl x509 -inform der; done > intermediates.pem
# extract signer cert
cat md.jwt | step crypto jwt inspect --insecure | jq -r '.header.x5c[0]' | base64 -d | openssl x509 -inform der -out mds.pem 
# validate mds ca path
openssl verify -CAfile root-r3.pem -untrusted intermediates.pem mds.pem
# verify jwt signature
cat md.jwt | step crypto jwt verify --key mds.pem --alg RS256 --subtle > md.jwt.json
# extract verified metadata
cat md.jwt.json | jq .payload > md.json

### STEP 4 : validate attestation

# parse attestation data
cat attestation.bin | ./attestation.php > attestation.yaml
# extract attestation certificate
cat attestation.yaml | yq .attestation.certificate | xxd -r -p | openssl x509 -inform der -out attestation-certificate.pem
# extract authData
cat attestation.yaml | yq .attestation.authData | xxd -r -p > authData.cbor
# decode authData
cat authData.cbor | cbor2json | jq '.data[]' | perl -ne 'printf("%02x",$_)' | xxd -r -p > authData.bin
# parse authData
cat authData.bin | ./authData.php > authData.yaml
# verify aaguid from attestation certificate matches aaguid in attested credential data
openssl asn1parse -in attestation-certificate.pem | grep 1.3.6.1.4.1.45724.1.1.4 -A1 | tail -1 | grep -o '\[HEX DUMP\]:.*' | cut -d: -f2 | xxd -r -p | openssl asn1parse -inform der | grep -o '\[HEX DUMP\]:.*' | cut -d: -f2 | tr A-Z a-z | diff - <(cat authData.yaml | yq .authdata.attestedCredentialData.aaguid) && /bin/echo -n "OK: AAGUID matches "
# lookup aaguid in metadata
jq --arg aaguid $(cat authData.yaml | yq .authdata.attestedCredentialData.aaguid) -f aaguid.jq md.json
# extract attestation root certificate from metadata
jq -r --arg aaguid $(cat authData.yaml | yq .authdata.attestedCredentialData.aaguid) -f attestationRootCertificate.jq md.json | base64 -d | openssl x509 -inform der > attestationRootCertificate.pem
# validate attestation ca path
openssl verify -CAfile attestationRootCertificate.pem attestation-certificate.pem 
# extract attestation pubkey
openssl x509 -in attestation-certificate.pem -noout -pubkey > attestation-pubkey.pem
# extract attestation signature
cat attestation.yaml | yq .attestation.signature | xxd -r -p > attestation-signature.bin
# reconstruct signed data
cat challengefile | openssl sha256 -binary > clientdatahash
cat authData.bin clientdatahash > signeddata
# verify attestation signature
openssl dgst -sha256 -verify attestation-pubkey.pem -signature attestation-signature.bin signeddata

# parse pubkey
cat sk.pub | cut -d' ' -f2 | base64 -d | ./ecdsa_sk.php > sk.yaml
# verify pubkey matches attestation credential data
diff <(cat authData.yaml | yq '.authdata.attestedCredentialData.credentialPublicKey|("04" + .x + .y)') <(cat sk.yaml | yq .ecdsa_sk.q) && echo OK: pubkey matches
# verify rpIdHash matches
diff <(/bin/echo -n ssh:sign | openssl sha256 -binary |xxd -p -c32) <(cat authData.yaml | yq .authdata.rpIdHash) && echo OK: RP ID ssh:sign matches
