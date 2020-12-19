import json

ISSUER_NAME = "fake_cert_authority1"

def create_fake_certificate(pem_public_key, subject, issuer_private_key):
    certificate_data = {}
    certificate_data["subject"] = subject
    certificate_data["issuer"] = ISSUER_NAME
    certificate_data["public_key"] = pem_public_key.decode('utf-8')
    raw_bytes = json.dumps(certificate_data).encode('utf-8')
    signature = issuer_private_key.sign(raw_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())

    return raw_bytes + signature

def validate_certificate(certificate_bytes, issuer_public_key):
    raw_cert_bytes, signature = certificate_bytes[:-256], certificate_bytes[-256:]
    issuer_public_key.verify(signature,raw_cert_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
    cert_data = json.loads(raw_cert_bytes.decode('utf-8'))
    cert_data["public_key"] = cert_data["public_key"].encode('utf-8')
    return cert_data
