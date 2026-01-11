#!/bin/bash
set -e

# Define colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}AZ Sentinel X Installation Script${NC}"
echo "----------------------------------------"
echo -e "${YELLOW}This script will install AZ Sentinel X on your system.${NC}"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Docker is not installed. Please install Docker first.${NC}"
    echo "Visit https://docs.docker.com/get-docker/ for installation instructions."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}Docker Compose is not installed. Please install Docker Compose first.${NC}"
    echo "Visit https://docs.docker.com/compose/install/ for installation instructions."
    exit 1
fi

# Ask for installation directory
read -p "Enter installation directory [/opt/azsentinel]: " INSTALL_DIR
INSTALL_DIR=${INSTALL_DIR:-/opt/azsentinel}

# Create installation directory if it doesn't exist
if [ ! -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}Creating installation directory: $INSTALL_DIR${NC}"
    sudo mkdir -p "$INSTALL_DIR"
    sudo chown $(whoami):$(whoami) "$INSTALL_DIR"
fi

# Copy files to installation directory
echo -e "${YELLOW}Copying files to $INSTALL_DIR...${NC}"
rsync -av --exclude='.git' --exclude='node_modules' --exclude='__pycache__' . "$INSTALL_DIR/"

# Create .env file if it doesn't exist
if [ ! -f "$INSTALL_DIR/.env" ]; then
    echo -e "${YELLOW}Creating .env file...${NC}"
    cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
    echo -e "${GREEN}Created .env file.${NC}"
    echo -e "${RED}Please edit $INSTALL_DIR/.env with your configuration!${NC}"
fi

# Set up systemd service if needed
read -p "Do you want to set up AZ Sentinel X as a systemd service? (y/n): " SETUP_SERVICE
if [[ "$SETUP_SERVICE" == "y" || "$SETUP_SERVICE" == "Y" ]]; then
    echo -e "${YELLOW}Setting up systemd service...${NC}"
    sudo cp "$INSTALL_DIR/scripts/azsentinel.service" /etc/systemd/system/
    sudo sed -i "s|WorkingDirectory=.*|WorkingDirectory=$INSTALL_DIR|g" /etc/systemd/system/azsentinel.service
    sudo systemctl daemon-reload
    echo -e "${GREEN}Systemd service set up successfully.${NC}"
    echo "You can start the service with: sudo systemctl start azsentinel"
    echo "You can enable it to start at boot with: sudo systemctl enable azsentinel"
fi

# Final instructions
echo ""
echo -e "${GREEN}AZ Sentinel X has been installed successfully!${NC}"
echo "----------------------------------------"
echo "Next steps:"
echo "1. Edit the .env file: $INSTALL_DIR/.env"
echo "2. Start the application:"
echo "   - Using Make: cd $INSTALL_DIR && make up"
echo "   - Using systemd: sudo systemctl start azsentinel"
echo ""
echo "The application will be accessible at http://10.144.90.95:5000"
echo "Default admin credentials: admin / admin123"
echo -e "${RED}Make sure to change the default password after first login!${NC}"
echo "----------------------------------------"