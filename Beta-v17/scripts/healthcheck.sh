#!/bin/bash
set -e

# Define colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}AZ Sentinel X Health Check${NC}"
echo "----------------------------------------"

# Check if Docker is running
echo -n "Checking Docker service... "
if systemctl is-active --quiet docker; then
    echo -e "${GREEN}RUNNING${NC}"
else
    echo -e "${RED}NOT RUNNING${NC}"
    echo "Please start Docker: sudo systemctl start docker"
    exit 1
fi

# Check if containers are running
echo -n "Checking AZ Sentinel X containers... "
if docker-compose ps | grep -q "Up"; then
    echo -e "${GREEN}RUNNING${NC}"
else
    echo -e "${RED}NOT RUNNING${NC}"
    echo "Please start containers: make up"
    exit 1
fi

# Check database connection
echo -n "Checking database connection... "
if docker-compose exec -T db pg_isready -U $POSTGRES_USER -h localhost > /dev/null 2>&1; then
    echo -e "${GREEN}CONNECTED${NC}"
else
    echo -e "${RED}NOT CONNECTED${NC}"
    echo "Database connection failed. Check logs: docker-compose logs db"
    exit 1
fi

# Check Web Server
echo -n "Checking web server... "
if curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/ | grep -q "200\|302"; then
    echo -e "${GREEN}RUNNING${NC}"
else
    echo -e "${RED}NOT RESPONDING${NC}"
    echo "Web server is not responding. Check logs: docker-compose logs app"
    exit 1
fi

# Check Wazuh API connectivity
echo -n "Checking Wazuh API connection... "
if curl -s -k -u "$WAZUH_API_USER:$WAZUH_API_PASSWORD" -X GET "https://10.144.90.95:55000/version" -o /dev/null -w "%{http_code}" | grep -q "200"; then
    echo -e "${GREEN}CONNECTED${NC}"
else
    echo -e "${YELLOW}WARNING${NC}"
    echo "Could not connect to Wazuh API. Check credentials in .env file."
fi

# Check OpenSearch connectivity
echo -n "Checking OpenSearch connection... "
if curl -s -k -u "$OPENSEARCH_USER:$OPENSEARCH_PASSWORD" "https://10.144.90.95:9200" -o /dev/null -w "%{http_code}" | grep -q "200"; then
    echo -e "${GREEN}CONNECTED${NC}"
else
    echo -e "${YELLOW}WARNING${NC}"
    echo "Could not connect to OpenSearch. Check credentials in .env file."
fi

# Overall status
echo "----------------------------------------"
echo -e "${GREEN}Health Check Complete!${NC}"
echo ""
echo "If all checks passed, AZ Sentinel X is running correctly."
echo "If any warnings or errors were reported, please check the specific components."
echo ""
echo "You can access AZ Sentinel X at: http://10.144.90.95:5000"
echo "Default login: admin / admin123"
echo -e "${RED}Remember to change the default password!${NC}"
echo "----------------------------------------"