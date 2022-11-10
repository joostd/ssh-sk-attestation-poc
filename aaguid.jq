.devices[] | select(.selectors[] | select(.type=="x509Extension") and .parameters.key=="1.3.6.1.4.1.45724.1.1.4" and .parameters.value.value==$aaguid) | .displayName
