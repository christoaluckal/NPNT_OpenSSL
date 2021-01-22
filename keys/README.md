# This folder holds the keys that are used by the various codes <br>

1.	`dgca.cert` : This is the certificate file used during signing. Obtained directly.
2.	`private.pem` : This is the private key used during signing. Obtained directly.


### Following are generated when the steps are followed <br>

1.	`pugi_certificate.pem` : This is certificate file extracted from a signed XML document using the XML processing code.
2.	`pugi_gen_public.pem` : This is the public key generated from pugi_certificate.pem using `openssl x509 -pubkey -noout -in pugi_certificate.pem  > pugi_gen_public.pem`
