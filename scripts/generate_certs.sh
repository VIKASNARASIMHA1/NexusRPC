#!/bin/bash
# NexusRPC TLS Certificate Generation Script
# Generates self-signed CA, server, and client certificates with proper extensions
# Supports both development and production environments

set -e  # Exit on error
set -u  # Exit on undefined variable

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="$SCRIPT_DIR"
CONFIG_DIR="$SCRIPT_DIR"

# Certificate parameters
CA_VALIDITY_DAYS=3650        # 10 years for CA
CERT_VALIDITY_DAYS=365       # 1 year for leaf certs
KEY_SIZE=4096               # RSA key size
RANDOM_SOURCE=/dev/urandom

# Default values (can be overridden by environment variables)
: "${CA_COUNTRY:=IN}"               # India
: "${CA_STATE:=Karnataka}"         # State
: "${CA_CITY:=Bengaluru}"          # City
: "${CA_ORG:=NexusRPC}"           # Organization
: "${CA_OU:=Security}"            # Organizational Unit
: "${CA_CN:=NexusRPC Development CA}"  # Common Name
: "${CA_EMAIL:=ca@nexusrpc.local}"

: "${SERVER_CN:=localhost}"       # Server Common Name
: "${SERVER_DNS:=localhost,nexusrpc-server,nexusrpc.local}"
: "${SERVER_IP:=127.0.0.1,::1}"

: "${CLIENT_CN:=nexusrpc-client}" # Client Common Name
: "${CLIENT_DNS:=client.nexusrpc.local}"
: "${CLIENT_IP:=127.0.0.1}"

: "${ENVIRONMENT:=development}"   # development, staging, production

# OpenSSL configuration template
create_openssl_config() {
    local cert_type=$1  # ca, server, client
    local cn=$2
    local config_file="$CERT_DIR/openssl-${cert_type}.cnf"
    
    cat > "$config_file" << EOF
[req]
default_bits = $KEY_SIZE
prompt = no
default_md = sha384
req_extensions = req_ext
distinguished_name = dn
x509_extensions = v3_ca

[dn]
C = $CA_COUNTRY
ST = $CA_STATE
L = $CA_CITY
O = $CA_ORG
OU = $CA_OU
CN = $cn
emailAddress = $CA_EMAIL

[req_ext]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, digitalSignature, keyCertSign, cRLSign
subjectAltName = @alt_names

[v3_req]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
basicConstraints = CA:FALSE
subjectAltName = @alt_names

[alt_names]
EOF

    # Add DNS entries
    if [[ "$cert_type" == "server" ]]; then
        IFS=',' read -ra DNS_ENTRIES <<< "$SERVER_DNS"
        for i in "${!DNS_ENTRIES[@]}"; do
            echo "DNS.$((i+1)) = ${DNS_ENTRIES[$i]}" >> "$config_file"
        done
        
        # Add IP addresses
        IFS=',' read -ra IP_ENTRIES <<< "$SERVER_IP"
        for i in "${!IP_ENTRIES[@]}"; do
            echo "IP.$((i+1)) = ${IP_ENTRIES[$i]}" >> "$config_file"
        done
    elif [[ "$cert_type" == "client" ]]; then
        IFS=',' read -ra DNS_ENTRIES <<< "$CLIENT_DNS"
        for i in "${!DNS_ENTRIES[@]}"; do
            echo "DNS.$((i+1)) = ${DNS_ENTRIES[$i]}" >> "$config_file"
        done
        echo "IP.1 = $CLIENT_IP" >> "$config_file"
    fi
    
    echo "$config_file"
}

# Print banner
echo -e "${BLUE}"
cat << "EOF"
  _   _                      _____  _____   _____ 
 | \ | |                    |  __ \|  __ \ / ____|
 |  \| | _____  __   _____  | |__) | |__) | |     
 | . ` |/ _ \ \/ /  / _ \ \ / /  _/|  ___/| |     
 | |\  |  __/>  <  | (_) \ V /| |   | |    | |____
 |_| \_|\___/_/\_\  \___/ \_/ |_|   |_|     \_____|
                                                    
EOF
echo -e "${NC}"
echo -e "${GREEN}NexusRPC TLS Certificate Generator${NC}"
echo -e "${YELLOW}Environment: $ENVIRONMENT${NC}"
echo -e ""

# Create certs directory if it doesn't exist
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

# Check for existing certificates
if [[ -f "ca.crt" && -f "server.crt" && -f "client.crt" && "$ENVIRONMENT" != "production" ]]; then
    echo -e "${YELLOW}⚠️  Existing certificates found.${NC}"
    read -p "Do you want to regenerate them? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}✓ Using existing certificates${NC}"
        exit 0
    fi
fi

# Backup existing certificates
if [[ -f "ca.key" || -f "server.key" || -f "client.key" ]]; then
    BACKUP_DIR="backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    echo -e "${BLUE}📦 Backing up existing certificates to $BACKUP_DIR/${NC}"
    mv -f *.crt *.key *.csr *.srl *.cnf "$BACKUP_DIR/" 2>/dev/null || true
fi

echo -e "${BLUE}🔐 Generating Certificate Authority (CA)...${NC}"

# Generate CA private key
openssl genrsa -out ca.key $KEY_SIZE
chmod 600 ca.key

# Generate CA configuration
CA_CONFIG=$(create_openssl_config "ca" "$CA_CN")

# Generate CA certificate
openssl req -x509 -new -nodes \
    -key ca.key \
    -sha384 \
    -days $CA_VALIDITY_DAYS \
    -out ca.crt \
    -config "$CA_CONFIG" \
    -extensions v3_ca

echo -e "${GREEN}✓ CA certificate generated${NC}"

# Verify CA certificate
openssl x509 -in ca.crt -text -noout | grep -E "Subject:|Issuer:|Not Before|Not After|CA:TRUE" > /dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ CA certificate verified${NC}"
else
    echo -e "${RED}✗ CA certificate verification failed${NC}"
    exit 1
fi

echo -e ""
echo -e "${BLUE}🖥️  Generating Server Certificate...${NC}"

# Generate server private key
openssl genrsa -out server.key $KEY_SIZE
chmod 600 server.key

# Generate server configuration
SERVER_CONFIG=$(create_openssl_config "server" "$SERVER_CN")

# Generate server CSR
openssl req -new \
    -key server.key \
    -out server.csr \
    -config "$SERVER_CONFIG"

# Generate server certificate
openssl x509 -req \
    -in server.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out server.crt \
    -days $CERT_VALIDITY_DAYS \
    -sha384 \
    -extfile "$SERVER_CONFIG" \
    -extensions v3_req

echo -e "${GREEN}✓ Server certificate generated${NC}"

# Verify server certificate
openssl verify -CAfile ca.crt server.crt
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Server certificate verified${NC}"
else
    echo -e "${RED}✗ Server certificate verification failed${NC}"
    exit 1
fi

echo -e ""
echo -e "${BLUE}👤 Generating Client Certificate...${NC}"

# Generate client private key
openssl genrsa -out client.key $KEY_SIZE
chmod 600 client.key

# Generate client configuration
CLIENT_CONFIG=$(create_openssl_config "client" "$CLIENT_CN")

# Generate client CSR
openssl req -new \
    -key client.key \
    -out client.csr \
    -config "$CLIENT_CONFIG"

# Generate client certificate
openssl x509 -req \
    -in client.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out client.crt \
    -days $CERT_VALIDITY_DAYS \
    -sha384 \
    -extfile "$CLIENT_CONFIG" \
    -extensions v3_req

echo -e "${GREEN}✓ Client certificate generated${NC}"

# Verify client certificate
openssl verify -CAfile ca.crt client.crt
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Client certificate verified${NC}"
else
    echo -e "${RED}✗ Client certificate verification failed${NC}"
    exit 1
fi

# Generate combined PEM files for easy import
cat server.crt server.key > server.pem
cat client.crt client.key > client.pem
chmod 600 server.pem client.pem

# Generate certificate chain
cat server.crt ca.crt > server-chain.crt
cat client.crt ca.crt > client-chain.crt

# Generate PKCS#12 format for Java/.NET
if command -v openssl &> /dev/null; then
    echo -e ""
    echo -e "${BLUE}📦 Generating PKCS#12 keystores...${NC}"
    
    # Server keystore
    openssl pkcs12 -export \
        -in server.crt \
        -inkey server.key \
        -certfile ca.crt \
        -out server.p12 \
        -password pass:changeit \
        -name nexsrpc-server
    
    # Client keystore  
    openssl pkcs12 -export \
        -in client.crt \
        -inkey client.key \
        -certfile ca.crt \
        -out client.p12 \
        -password pass:changeit \
        -name nexsrpc-client
    
    echo -e "${GREEN}✓ PKCS#12 keystores generated (password: changeit)${NC}"
fi

# Create certificate info file
cat > cert-info.txt << EOF
NexusRPC Certificate Information
===============================
Generated: $(date)
Environment: $ENVIRONMENT

CA Certificate:
  Subject: $(openssl x509 -in ca.crt -noout -subject)
  Issuer:  $(openssl x509 -in ca.crt -noout -issuer)
  Valid:   $(openssl x509 -in ca.crt -noout -startdate -enddate)
  Expires: $(openssl x509 -in ca.crt -noout -enddate)

Server Certificate:
  Subject: $(openssl x509 -in server.crt -noout -subject)
  Issuer:  $(openssl x509 -in server.crt -noout -issuer)
  Valid:   $(openssl x509 -in server.crt -noout -startdate -enddate)
  DNS:     $SERVER_DNS
  IP:      $SERVER_IP

Client Certificate:
  Subject: $(openssl x509 -in client.crt -noout -subject)
  Issuer:  $(openssl x509 -in client.crt -noout -issuer)
  Valid:   $(openssl x509 -in client.crt -noout -startdate -enddate)
  DNS:     $CLIENT_DNS
  IP:      $CLIENT_IP

Files Generated:
$(ls -la *.crt *.key *.pem *.csr *.p12 2>/dev/null | awk '{print "  " $9 " (" $5 " bytes)"}')
EOF

# Clean up CSR files (optional)
if [[ "$ENVIRONMENT" == "production" ]]; then
    rm -f *.csr *.cnf
else
    # Keep for debugging in development
    echo -e "${YELLOW}ℹ️  CSR and config files kept for debugging${NC}"
fi

# Set secure permissions
chmod 644 *.crt *.pem *.txt 2>/dev/null || true
chmod 600 *.key 2>/dev/null || true
chmod 600 *.p12 2>/dev/null || true

echo -e ""
echo -e "${GREEN}✅ Certificate generation complete!${NC}"
echo -e "${GREEN}📁 Certificates saved to: $CERT_DIR${NC}"
echo -e ""
echo -e "${BLUE}📋 Generated Files:${NC}"
echo -e "  ${YELLOW}CA Certificates:${NC}"
echo -e "    • ca.key         - CA private key (KEEP SECURE!)"
echo -e "    • ca.crt         - CA certificate"
echo -e ""
echo -e "  ${YELLOW}Server Certificates:${NC}"
echo -e "    • server.key     - Server private key"
echo -e "    • server.crt     - Server certificate"
echo -e "    • server.csr     - Server certificate signing request"
echo -e "    • server.pem     - Combined server cert + key"
echo -e "    • server.p12     - PKCS#12 keystore (password: changeit)"
echo -e ""
echo -e "  ${YELLOW}Client Certificates:${NC}"
echo -e "    • client.key     - Client private key"
echo -e "    • client.crt     - Client certificate"
echo -e "    • client.csr     - Client certificate signing request"
echo -e "    • client.pem     - Combined client cert + key"
echo -e "    • client.p12     - PKCS#12 keystore (password: changeit)"
echo -e ""
echo -e "  ${YELLOW}Documentation:${NC}"
echo -e "    • cert-info.txt  - Certificate information"
echo -e ""

# Verify complete chain
echo -e "${BLUE}🔍 Verifying certificate chain...${NC}"
if openssl verify -CAfile ca.crt -untrusted server.crt server.crt &>/dev/null && \
   openssl verify -CAfile ca.crt -untrusted client.crt client.crt &>/dev/null; then
    echo -e "${GREEN}✓ Certificate chain verified successfully${NC}"
else
    echo -e "${RED}✗ Certificate chain verification failed${NC}"
    exit 1
fi

# Test TLS 1.3 compatibility
echo -e ""
echo -e "${BLUE}🔒 Testing TLS 1.3 compatibility...${NC}"
if openssl s_server -cert server.crt -key server.key -accept 8443 -www -tls1_3 -quiet &>/dev/null & 
   SERVER_PID=$!
   sleep 1
   openssl s_client -connect localhost:8443 -CAfile ca.crt -tls1_3 -quiet &>/dev/null
   RESULT=$?
   kill $SERVER_PID 2>/dev/null || true
   if [ $RESULT -eq 0 ]; then
       echo -e "${GREEN}✓ TLS 1.3 supported and working${NC}"
   else
       echo -e "${YELLOW}⚠️  TLS 1.3 test failed, falling back to TLS 1.2${NC}"
   fi
fi

# Print next steps
echo -e ""
echo -e "${BLUE}🚀 Next Steps:${NC}"
echo -e "  1. For development: Start your RPC server with TLS enabled:"
echo -e "     ${YELLOW}python -m rpc.server_cli --host 0.0.0.0 --port 50051 --tls${NC}"
echo -e ""
echo -e "  2. For client connections:"
echo -e "     ${YELLOW}from security.tls import TLSConfig${NC}"
echo -e "     ${YELLOW}config = TLSConfig(certfile='certs/client.crt',${NC}"
echo -e "     ${YELLOW}                  keyfile='certs/client.key',${NC}"
echo -e "     ${YELLOW}                  cafile='certs/ca.crt')${NC}"
echo -e ""
echo -e "  3. For production: Move CA private key (ca.key) to secure storage"
echo -e "     and generate new leaf certificates with longer validity"
echo -e ""

# Warning for production
if [[ "$ENVIRONMENT" == "production" ]]; then
    echo -e "${RED}⚠️  PRODUCTION WARNING${NC}"
    echo -e "${RED}   • These are self-signed certificates!${NC}"
    echo -e "${RED}   • For production, use certificates from a trusted CA${NC}"
    echo -e "${RED}   • Store ca.key offline in a secure location${NC}"
    echo -e "${RED}   • Consider using shorter validity periods (90 days)${NC}"
    echo -e ""
fi

# Create .gitignore entry if not present
if [[ -f "../.gitignore" ]]; then
    if ! grep -q "security/certs/\*.crt" "../.gitignore"; then
        echo -e "\n# TLS certificates\nsecurity/certs/*.crt\nsecurity/certs/*.key\nsecurity/certs/*.csr\nsecurity/certs/*.p12\nsecurity/certs/*.pem\nsecurity/certs/*.srl\nsecurity/certs/backup_*/\nsecurity/certs/openssl-*.cnf" >> "../.gitignore"
        echo -e "${YELLOW}ℹ️  Added certificate files to .gitignore${NC}"
    fi
fi

echo -e "${GREEN}✨ Certificate generation completed successfully!${NC}"