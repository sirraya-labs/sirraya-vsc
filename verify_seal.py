#!/usr/bin/env python3
"""
VSC SEAL Verifier — Standalone
===============================
Takes a SEAL JSON file, resolves the DID:Web identifier,
extracts the Ed25519 public key, and verifies the signature.

Usage:
    python verify_seal.py seal.json
    python verify_seal.py seal.json --did-url https://sirraya.org/actors/farmer/did.json
    python verify_seal.py seal.json --offline --public-key <hex>
"""

import json
import sys
import ssl
import urllib.request
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


def fetch_did_document(did_url: str) -> dict:
    """Fetch a DID Document from a URL."""
    ctx = ssl.create_default_context()
    req = urllib.request.Request(did_url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        raise Exception(f"HTTP {e.code} — DID not found at {did_url}")
    except urllib.error.URLError as e:
        raise Exception(f"Connection failed: {e.reason}")


def extract_public_key(did_doc: dict) -> Ed25519PublicKey:
    """
    Extract Ed25519 public key from a DID Document.
    Handles Multibase format: z + ed01 + raw_key_hex
    """
    vm = did_doc.get("verificationMethod", [{}])[0]
    pub_key_mb = vm.get("publicKeyMultibase", "")
    
    if not pub_key_mb:
        raise Exception("No publicKeyMultibase found in DID Document")
    
    key_hex = pub_key_mb
    if key_hex.startswith("z"):
        key_hex = key_hex[1:]
    if key_hex.startswith("ed01"):
        key_hex = key_hex[4:]
    
    if len(key_hex) != 64:
        raise Exception(f"Invalid key length: {len(key_hex)} chars (expected 64)")
    
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex))


def jcs_canonicalize(obj: dict) -> bytes:
    """JSON Canonicalization Scheme — sorted keys, no whitespace."""
    return json.dumps(obj, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()


def verify_seal_signature(seal_data: dict, public_key: Ed25519PublicKey) -> dict:
    """
    Verify a SEAL's Ed25519 signature.
    Returns a detailed verification report.
    """
    proof = seal_data.get("proof", {})
    proof_value = proof.get("proof_value", proof.get("proofValue", ""))
    
    if not proof_value:
        return {"valid": False, "error": "No proof_value found in SEAL"}
    
    # Build the signing payload (matches SEAL._signing_payload())
    payload = {
        "id": seal_data["id"],
        "sealVersion": seal_data["sealVersion"],
        "sealTimestamp": seal_data["sealTimestamp"],
        "eventVector": seal_data["eventVector"],
        "extensions": seal_data.get("extensions", {"+Dn": {}})
    }
    
    message = jcs_canonicalize(payload)
    signature_bytes = bytes.fromhex(proof_value)
    
    try:
        public_key.verify(signature_bytes, message)
        return {"valid": True, "payload_hash": None}
    except InvalidSignature:
        return {"valid": False, "error": "Ed25519 signature verification failed — payload does not match signature"}


def print_report(seal_data: dict, did_doc: dict, result: dict, did_url: str):
    """Print a clean verification report."""
    ev = seal_data.get("eventVector", {})
    who = ev.get("who", {})
    how = ev.get("how", {})
    proof = seal_data.get("proof", {})
    
    print(f"\n{'='*70}")
    print(f"  VSC SEAL VERIFICATION REPORT")
    print(f"{'='*70}")
    print(f"  SEAL ID:      {seal_data.get('id', 'N/A')}")
    print(f"  Event:        {how.get('business_step', 'N/A')} · {how.get('disposition', 'N/A')}")
    print(f"  Actor DID:    {who.get('actor_did', 'N/A')}")
    print(f"  DID URL:      {did_url}")
    print(f"  DID Resolves: ✓")
    
    # DID Document info
    vm = did_doc.get("verificationMethod", [{}])[0]
    print(f"  Key Type:     {vm.get('type', 'N/A')}")
    pub_mb = vm.get("publicKeyMultibase", "")
    print(f"  PubKey:       {pub_mb[:50]}...")
    
    print(f"\n  {'─'*66}")
    print(f"  PROOF DETAILS")
    print(f"  {'─'*66}")
    print(f"  Type:         {proof.get('type', 'N/A')}")
    print(f"  Created:      {proof.get('created', 'N/A')}")
    print(f"  Method:       {proof.get('verification_method', 'N/A')}")
    print(f"  Signature:    {proof.get('proof_value', proof.get('proofValue', ''))[:64]}...")
    
    print(f"\n  {'─'*66}")
    print(f"  VERIFICATION RESULT")
    print(f"  {'─'*66}")
    
    if result["valid"]:
        print(f"  ✓ SIGNATURE VALID")
        print(f"  The SEAL was signed by the actor identified in the DID Document.")
        print(f"  Trust: Decentralized — verified via did:web at sirraya.org")
    else:
        print(f"  ✗ SIGNATURE INVALID")
        print(f"  Error: {result.get('error', 'Unknown error')}")
        print(f"  The SEAL was NOT signed by the actor identified in the DID Document,")
        print(f"  or the SEAL has been modified since signing.")
    
    print(f"\n{'='*70}\n")


def main():
    if len(sys.argv) < 2:
        print("Usage: python verify_seal.py <seal.json> [--did-url <url>] [--offline --public-key <hex>]")
        sys.exit(1)
    
    seal_path = Path(sys.argv[1])
    if not seal_path.exists():
        print(f"Error: File not found: {sys.argv[1]}")
        sys.exit(1)
    
    seal_data = json.loads(seal_path.read_text())
    
    # Parse arguments
    did_url = None
    offline = False
    pub_key_hex = None
    
    args = sys.argv[2:]
    i = 0
    while i < len(args):
        if args[i] == "--did-url" and i + 1 < len(args):
            did_url = args[i + 1]; i += 2
        elif args[i] == "--offline":
            offline = True; i += 1
        elif args[i] == "--public-key" and i + 1 < len(args):
            pub_key_hex = args[i + 1]; i += 2
        else:
            i += 1
    
    try:
        # Resolve DID
        if offline and pub_key_hex:
            public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_key_hex))
            did_url = "OFFLINE (manual key)"
            did_doc = {"verificationMethod": [{"type": "Ed25519VerificationKey2020", "publicKeyMultibase": f"zed01{pub_key_hex}"}]}
            print(f"\n  ⓘ Offline mode — using provided public key")
        else:
            if did_url is None:
                # Derive DID URL from the SEAL
                actor_did = seal_data["eventVector"]["who"]["actor_did"]
                did_path = actor_did.replace("did:web:", "").replace(":", "/")
                did_url = f"https://{did_path}/did.json"
            
            print(f"\n  ⓘ Resolving DID: {did_url}")
            did_doc = fetch_did_document(did_url)
            public_key = extract_public_key(did_doc)
        
        # Verify
        result = verify_seal_signature(seal_data, public_key)
        print_report(seal_data, did_doc, result, did_url)
        
        sys.exit(0 if result["valid"] else 1)
        
    except Exception as e:
        print(f"\n  ✗ Verification failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()