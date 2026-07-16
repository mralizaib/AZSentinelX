#!/bin/bash
set -e

# Define colors
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Generate a random 64-character string for use as SESSION_SECRET
SECRET=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1)

echo -e "${GREEN}Generated Session Secret${NC}"
echo "----------------------------------------"
echo "Use this value for SESSION_SECRET in .env file:"
echo ""
echo $SECRET
echo ""
echo "To automatically update your .env file, run:"
echo "sed -i 's/^SESSION_SECRET=.*/SESSION_SECRET=$SECRET/' .env"
echo "----------------------------------------"

# Offer to update .env file automatically
if [ -f .env ]; then
    read -p "Do you want to update SESSION_SECRET in your .env file? (y/n): " update
    if [[ "$update" == "y" || "$update" == "Y" ]]; then
        sed -i "s/^SESSION_SECRET=.*/SESSION_SECRET=$SECRET/" .env
        echo -e "${GREEN}Updated SESSION_SECRET in .env file.${NC}"
    fi
fi