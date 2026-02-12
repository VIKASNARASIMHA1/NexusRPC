#!/bin/bash
# NexusRPC TLS Certificate Generation Script
# Generates self-signed CA, server, and client certificates with proper extensions

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

# Certificate parameters
CA_VALIDITY_DAYS=3650        # 10 years for CA
CERT_VALIDITY_DAYS=365       # 1 year for leaf certs
KEY_SIZE=4096               # RSA key size
RANDOM_SOURCE=/dev/urandom

# Default values
: "${CA_COUNTRY:=IN}"
: "${CA_STATE:=Karnataka}"
: "${CA_CITY:=Bengaluru}"
: "${CA_ORG:=NexusRPC}"
: "${CA_OU:=Security}"
: "${CA_CN:=NexusRPC Development CA}"
: "${CA_EMAIL:=ca@nexusrpc.local}"

: "${SERVER_CN:=localhost}"
: "${SERVER_DNS:=localhost,nexusrpc-server,nexusrpc.local}"
: "${SERVER_IP:=127.0.0.1,::1}"

: "${CLIENT_CN:=nexusrpc-client}"
: "${CLIENT_DNS:=client.nexusrpc.local}"
: "${CLIENT_IP:=127.0.0.1}"

: "${ENVIRONMENT:=development}"

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
echo ""

# Create certs directory if it doesn't exist
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

# Backup existing certificates
if ls *.crt *.key *.csr *.pem *.p12 2>/dev/null; then
    BACKUP_DIR="backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    echo -e "${BLUE}📦 Backing up existing certificates to $BACKUP_DIR/${NC}"
    mv -f *.crt *.key *.csr *.pem *.p12 *.srl *.cnf "$BACKUP_DIR/" 2>/dev/null || true
fi

echo -e "${BLUE}🔐 Generating Certificate Authority (CA)...${NC}"

# Generate CA private key
openssl genrsa -out ca.key $KEY_SIZE
chmod 600 ca.key

# Generate CA certificate (self-signed)
openssl req -x509 -new -nodes \
    -key ca.key \
    -sha384 \
    -days $CA_VALIDITY_DAYS \
    -out ca.crt \
    -subj "/C=$CA_COUNTRY/ST=$CA_STATE/L=$CA_CITY/O=$CA_ORG/OU=$CA_OU/CN=$CA_CN/emailAddress=$CA_EMAIL" \
    -extensions v3_ca

echo -e "${GREEN}✓ CA certificate generated${NC}"

# Verify CA certificate
echo -e "${BLUE}🔍 Verifying CA certificate...${NC}"
openssl x509 -in ca.crt -text -noout | grep -E "Subject:|Issuer:|Not Before|Not After|CA:TRUE" || true

# Generate CA certificate chain
cp ca.crt ca-chain.crt

echo -e ""
echo -e "${BLUE}🖥️  Generating Server Certificate...${NC}"

# Generate server private key
openssl genrsa -out server.key $KEY_SIZE
chmod 600 server.key

# Create server OpenSSL config
cat > openssl-server.cnf << EOF
[req]
default_bits = $KEY_SIZE
prompt = no
default_md = sha384
req_extensions = req_ext
distinguished_name = dn
x509_extensions = v3_req

[dn]
C = $CA_COUNTRY
ST = $CA_STATE
L = $CA_CITY
O = $CA_ORG
OU = $CA_OU
CN = $SERVER_CN
emailAddress = $CA_EMAIL

[req_ext]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[v3_req]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
basicConstraints = CA:FALSE
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = nexsrpc-server
DNS.3 = nexsrpc.local
DNS.4 = *.nexusrpc.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Generate server CSR
openssl req -new \
    -key server.key \
    -out server.csr \
    -config openssl-server.cnf

# Generate server certificate signed by CA
openssl x509 -req \
    -in server.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out server.crt \
    -days $CERT_VALIDITY_DAYS \
    -sha384 \
    -extfile openssl-server.cnf \
    -extensions v3_req

echo -e "${GREEN}✓ Server certificate generated${NC}"

# Verify server certificate
echo -e "${BLUE}🔍 Verifying server certificate...${NC}"
openssl verify -CAfile ca.crt server.crt

# Create server PEM (cert + key)
cat server.crt server.key > server.pem
chmod 600 server.pem

echo -e ""
echo -e "${BLUE}👤 Generating Client Certificate...${NC}"

# Generate client private key
openssl genrsa -out client.key $KEY_SIZE
chmod 600 client.key

# Create client OpenSSL config
cat > openssl-client.cnf << EOF
[req]
default_bits = $KEY_SIZE
prompt = no
default_md = sha384
req_extensions = req_ext
distinguished_name = dn
x509_extensions = v3_req

[dn]
C = $CA_COUNTRY
ST = $CA_STATE
L = $CA_CITY
O = $CA_ORG
OU = $CA_OU
CN = $CLIENT_CN
emailAddress = $CA_EMAIL

[req_ext]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = clientAuth
subjectAltName = @alt_names

[v3_req]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
basicConstraints = CA:FALSE
subjectAltName = @alt_names

[alt_names]
DNS.1 = client.nexusrpc.local
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

# Generate client CSR
openssl req -new \
    -key client.key \
    -out client.csr \
    -config openssl-client.cnf

# Generate client certificate signed by CA
openssl x509 -req \
    -in client.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out client.crt \
    -days $CERT_VALIDITY_DAYS \
    -sha384 \
    -extfile openssl-client.cnf \
    -extensions v3_req

echo -e "${GREEN}✓ Client certificate generated${NC}"

# Verify client certificate
echo -e "${BLUE}🔍 Verifying client certificate...${NC}"
openssl verify -CAfile ca.crt client.crt

# Create client PEM (cert + key)
cat client.crt client.key > client.pem
chmod 600 client.pem

# Generate PKCS#12 keystores
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

# Truststore
openssl pkcs12 -export \
    -nokeys \
    -in ca.crt \
    -out truststore.p12 \
    -password pass:changeit \
    -name nexsrpc-ca

echo -e "${GREEN}✓ PKCS#12 keystores generated (password: changeit)${NC}"

# Generate certificate info file
cat > cert-info.txt << EOF
NexusRPC Certificate Information
===============================
Generated: $(date)
Environment: $ENVIRONMENT

CA Certificate:
  Subject: $(openssl x509 -in ca.crt -noout -subject)
  Issuer:  $(openssl x509 -in ca.crt -noout -issuer)
  Valid:   $(openssl x509 -in ca.crt -noout -startdate)
  Expires: $(openssl x509 -in ca.crt -noout -enddate)
  Serial:  $(openssl x509 -in ca.crt -noout -serial | cut -d= -f2)

Server Certificate:
  Subject: $(openssl x509 -in server.crt -noout -subject)
  Issuer:  $(openssl x509 -in server.crt -noout -issuer)
  Valid:   $(openssl x509 -in server.crt -noout -startdate)
  Expires: $(openssl x509 -in server.crt -noout -enddate)
  Serial:  $(openssl x509 -in server.crt -noout -serial | cut -d= -f2)

Client Certificate:
  Subject: $(openssl x509 -in client.crt -noout -subject)
  Issuer:  $(openssl x509 -in client.crt -noout -issuer)
  Valid:   $(openssl x509 -in client.crt -noout -startdate)
  Expires: $(openssl x509 -in client.crt -noout -enddate)
  Serial:  $(openssl x509 -in client.crt -noout -serial | cut -d= -f2)

Files Generated:
$(ls -la *.crt *.key *.csr *.pem *.p12 2>/dev/null | awk '{print "  " $9 " (" $5 " bytes)"}')
EOF

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
echo -e "    • server.csr     - Server CSR"
echo -e "    • server.pem     - Combined server cert + key"
echo -e "    • server.p12     - PKCS#12 keystore (password: changeit)"
echo -e ""
echo -e "  ${YELLOW}Client Certificates:${NC}"
echo -e "    • client.key     - Client private key"
echo -e "    • client.crt     - Client certificate"
echo -e "    • client.csr     - Client CSR"
echo -e "    • client.pem     - Combined client cert + key"
echo -e "    • client.p12     - PKCS#12 keystore (password: changeit)"
echo -e ""
echo -e "  ${YELLOW}Trust Store:${NC}"
echo -e "    • truststore.p12 - Truststore with CA (password: changeit)"
echo -e ""

# Verify complete chain
echo -e "${BLUE}🔍 Verifying certificate chain...${NC}"
if openssl verify -CAfile ca.crt server.crt >/dev/null 2>&1 && \
   openssl verify -CAfile ca.crt client.crt >/dev/null 2>&1; then
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
   sleep 2
   openssl s_client -connect localhost:8443 -CAfile ca.crt -tls1_3 -quiet &>/dev/null
   RESULT=$?
   kill $SERVER_PID 2>/dev/null || true
   if [ $RESULT -eq 0 ]; then
       echo -e "${GREEN}✓ TLS 1.3 supported and working${NC}"
   else
       echo -e "${YELLOW}⚠️  TLS 1.3 test failed, using TLS 1.2${NC}"
   fi
fi

# Create .gitignore
cat > .gitignore << EOF
# Private keys
*.key
*.key.*

# Certificate signing requests
*.csr

# Keystores
*.p12
*.jks
*.keystore

# PEM files with private keys
*.pem

# Serial files
*.srl

# Backup directories
backup_*/

# Don't ignore certificates
!ca.crt
!server.crt
!client.crt
!chain.crt
EOF

echo -e ""
echo -e "${GREEN}✨ Certificate generation completed successfully!${NC}"
echo -e ""
echo -e "${BLUE}🚀 Next Steps:${NC}"
echo -e "  1. For development: Start your RPC server:"
echo -e "     ${YELLOW}python -m rpc.server_cli --host 0.0.0.0 --port 50051 --tls${NC}"
echo -e ""
echo -e "  2. For client connections:"
echo -e "     ${YELLOW}from security.tls import TLSConfig${NC}"
echo -e "     ${YELLOW}config = TLSConfig(${NC}"
echo -e "     ${YELLOW}    certfile='security/certs/client.crt',${NC}"
echo -e "     ${YELLOW}    keyfile='security/certs/client.key',${NC}"
echo -e "     ${YELLOW}    cafile='security/certs/ca.crt'${NC}"
echo -e "     ${YELLOW})${NC}"