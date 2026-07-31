#!/bin/bash
set -e

# Define colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Define output package name
PACKAGE_NAME="azsentinel-deployment-$(date +%Y%m%d).tar.gz"

echo -e "${GREEN}AZ Sentinel X Deployment Package Creator${NC}"
echo "----------------------------------------"

# Create a temporary directory for the package
TEMP_DIR=$(mktemp -d)
echo -e "${YELLOW}Creating temporary directory: $TEMP_DIR${NC}"

# List of files to include in the package
FILES_TO_INCLUDE=(
    "docker-compose.yml"
    "Dockerfile"
    "requirements-docker.txt"
    ".env.example"
    "Makefile"
    "DEPLOYMENT.md"
    "QUICKSTART.md"
    "scripts/init_db.sh"
    "scripts/docker-entrypoint.sh"
    "scripts/backup-restore.sh"
    "scripts/install.sh"
    "scripts/healthcheck.sh"
    "scripts/generate-secret.sh"
    "scripts/azsentinel.service"
    "scripts/nginx/azsentinel.conf"
)

# Copy files to the temporary directory preserving directory structure
echo -e "${YELLOW}Copying deployment files...${NC}"
for file in "${FILES_TO_INCLUDE[@]}"; do
    # Create the directory structure
    mkdir -p "$TEMP_DIR/$(dirname $file)"
    
    # Copy the file
    if [ -f "$file" ]; then
        cp "$file" "$TEMP_DIR/$file"
    else
        echo -e "${RED}Warning: File $file not found, skipping...${NC}"
    fi
done

# Create the package
echo -e "${YELLOW}Creating deployment package...${NC}"
(cd "$TEMP_DIR" && tar -czf "$PACKAGE_NAME" .)
mv "$TEMP_DIR/$PACKAGE_NAME" .

# Clean up
rm -rf "$TEMP_DIR"

echo -e "${GREEN}Deployment package created: $PACKAGE_NAME${NC}"
echo "----------------------------------------"
echo "This package contains all necessary files for deploying AZ Sentinel X"
echo "in a local Docker environment with server address 10.144.90.95."
echo ""
echo "To use this package:"
echo "1. Extract the package: tar -xzf $PACKAGE_NAME"
echo "2. Follow the instructions in DEPLOYMENT.md"
echo "3. Run the installation script: ./scripts/install.sh"
echo ""
echo "Default admin credentials: admin / admin123"
echo -e "${RED}Make sure to change the default password after first login!${NC}"
echo "----------------------------------------"