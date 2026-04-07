# TLSentinel Scripts

Requires **tlsentinel-server >= v2026.4.4**. Federation metadata imports with dual signing/encryption certificates require this version or later for correct cert use labelling.

Utility scripts for interacting with the TLSentinel API. All scripts use Python stdlib only — no dependencies required unless noted.

---

## login.py

Authenticate and print a bearer token. Capture it into a shell variable for use with the other scripts.

```bash
TOKEN=$(python login.py --server https://tlsentinel.example.com --username admin)
```

Password is prompted securely if `--password` is omitted.

---

## import_cert.py

Ingest a certificate file into TLSentinel. Optionally create or link to an endpoint.

**Supported formats:** `.pem`, `.crt`, `.cer`, `.der`, `.p12`, `.pfx`

PKCS#12 support requires the `cryptography` package:
```bash
pip install cryptography
```

**Examples:**

```bash
# Ingest a PEM — cert only, no endpoint
python import_cert.py partner.pem \
    --server https://tlsentinel.example.com --token "$TOKEN"

# Ingest a DER and create a new manual endpoint
python import_cert.py partner.cer \
    --server https://tlsentinel.example.com --token "$TOKEN" \
    --create-endpoint --endpoint-name "Acme Supplier"

# Ingest a P12 and link to an existing endpoint by name
python import_cert.py partner.p12 --p12-password secret \
    --server https://tlsentinel.example.com --token "$TOKEN" \
    --endpoint-name "Acme Supplier"

# Ingest and link to an existing endpoint by ID
python import_cert.py partner.pem \
    --server https://tlsentinel.example.com --token "$TOKEN" \
    --endpoint-id <uuid>

# Dry run — detect file type without calling the API
python import_cert.py partner.pem --dry-run
```

---

## import_metadata_certs.py

Parse an XML metadata file or URL, extract all embedded X.509 certificates, and ingest them into TLSentinel. Optionally create or link to a SAML endpoint.

Works with any XML using `<ds:X509Certificate>` elements — SAML `EntityDescriptor` and `EntitiesDescriptor` (federation aggregate) documents. Correctly maps `signing` and `encryption` cert use from the metadata.

**Examples:**

```bash
# Dry run — see what certs are in the file without touching the API
python import_metadata_certs.py metadata.xml --dry-run

# Ingest certs only, no endpoint
python import_metadata_certs.py metadata.xml \
    --server https://tlsentinel.example.com --token "$TOKEN"

# Ingest directly from a URL and create a new SAML endpoint
python import_metadata_certs.py \
    https://login.microsoftonline.com/tenant/federationmetadata/2007-06/federationmetadata.xml \
    --server https://tlsentinel.example.com --token "$TOKEN" \
    --create-endpoint --endpoint-name "Azure AD"

# Ingest from a local file and create a new SAML endpoint
python import_metadata_certs.py metadata.xml \
    --server https://tlsentinel.example.com --token "$TOKEN" \
    --create-endpoint --endpoint-name "Okta IdP" \
    --metadata-url https://okta.example.com/app/sso/saml/metadata

# Link to an existing endpoint by name
python import_metadata_certs.py metadata.xml \
    --server https://tlsentinel.example.com --token "$TOKEN" \
    --endpoint-name "Okta IdP"
```

---

## import_metadata_folder.py

Bulk import a folder of SAML metadata XML files. For each file:

- Uses the filename (without extension) as the endpoint name
- Checks if a SAML endpoint with that name already exists
- Creates one if it does not
- Ingests all certificates found in the XML and links them to the endpoint with the correct `certUse` (signing/encryption)

Useful for onboarding a directory of trading partner or IdP metadata files in one pass.

**Examples:**

```bash
# Dry run — show what would be imported without touching the API
python import_metadata_folder.py ./metadata/ --dry-run

# Bulk import all XML files in the folder
python import_metadata_folder.py ./metadata/ \
    --server https://tlsentinel.example.com --token "$TOKEN"
```

Given a folder like:
```
metadata/
  okta_idp.xml
  azure_ad.xml
  acme_partner.xml
```

This creates three SAML endpoints named `okta_idp`, `azure_ad`, and `acme_partner`, each with their signing and encryption certs ingested and linked.

---

## Typical workflow

```bash
# 1. Get a token
TOKEN=$(python login.py --server https://tlsentinel.example.com --username admin)

# 2. Import a trading partner cert and create an endpoint for it
python import_cert.py acme_signing.cer \
    --server https://tlsentinel.example.com --token "$TOKEN" \
    --create-endpoint --endpoint-name "Acme Supplier"

# 3. Import IdP metadata and create a SAML endpoint
python import_metadata_certs.py \
    https://idp.example.com/saml/metadata \
    --server https://tlsentinel.example.com --token "$TOKEN" \
    --create-endpoint --endpoint-name "Corporate IdP"

# 4. Bulk import a folder of trading partner metadata files
python import_metadata_folder.py ./metadata/ \
    --server https://tlsentinel.example.com --token "$TOKEN"
```
