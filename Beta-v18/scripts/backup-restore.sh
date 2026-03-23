#!/bin/bash
set -e

# Define colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Display help message
show_help() {
    echo "AZ Sentinel X Database Backup and Restore Script"
    echo "------------------------------------------------"
    echo "Usage: $0 [backup|restore] [backup_file]"
    echo ""
    echo "Commands:"
    echo "  backup        Create a new backup of the PostgreSQL database"
    echo "  restore       Restore a backup to the PostgreSQL database"
    echo ""
    echo "Examples:"
    echo "  $0 backup                  # Create a backup with timestamp"
    echo "  $0 backup my_backup.sql    # Create a backup with specified name"
    echo "  $0 restore backups/my_backup.sql  # Restore from specified backup"
    echo ""
}

# Check if Docker is running and containers are up
check_docker() {
    if ! docker-compose ps | grep -q db; then
        echo -e "${RED}PostgreSQL container is not running. Please start it first:${NC}"
        echo "docker-compose up -d db"
        exit 1
    fi
}

# Create database backup
create_backup() {
    BACKUP_DIR="backups"
    mkdir -p $BACKUP_DIR

    if [ -z "$1" ]; then
        BACKUP_FILE="$BACKUP_DIR/azsentinel_$(date +%Y%m%d_%H%M%S).sql"
    else
        BACKUP_FILE="$1"
    fi

    echo -e "${YELLOW}Creating database backup to $BACKUP_FILE...${NC}"
    docker-compose exec -T db pg_dump -U $POSTGRES_USER $POSTGRES_DB > $BACKUP_FILE
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Backup created successfully!${NC}"
        echo "Backup location: $BACKUP_FILE"
    else
        echo -e "${RED}Backup failed!${NC}"
        exit 1
    fi
}

# Restore database from backup
restore_backup() {
    BACKUP_FILE=$1
    
    if [ -z "$BACKUP_FILE" ]; then
        echo -e "${RED}Error: No backup file specified for restore.${NC}"
        show_help
        exit 1
    fi
    
    if [ ! -f "$BACKUP_FILE" ]; then
        echo -e "${RED}Error: Backup file '$BACKUP_FILE' does not exist.${NC}"
        exit 1
    fi
    
    echo -e "${YELLOW}Warning: This will overwrite the current database!${NC}"
    read -p "Are you sure you want to proceed? (y/n): " confirm
    
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "Restoration cancelled."
        exit 0
    fi
    
    echo -e "${YELLOW}Restoring database from $BACKUP_FILE...${NC}"
    cat $BACKUP_FILE | docker-compose exec -T db psql -U $POSTGRES_USER $POSTGRES_DB
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Database restored successfully!${NC}"
    else
        echo -e "${RED}Database restoration failed!${NC}"
        exit 1
    fi
}

# Load environment variables
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
else
    echo -e "${RED}Error: .env file not found.${NC}"
    echo "Please create a .env file with the following variables:"
    echo "POSTGRES_USER=azsentinel"
    echo "POSTGRES_DB=azsentinel"
    exit 1
fi

# Check command line arguments
if [ $# -lt 1 ]; then
    show_help
    exit 1
fi

# Execute the requested command
case "$1" in
    backup)
        check_docker
        create_backup $2
        ;;
    restore)
        check_docker
        restore_backup $2
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        show_help
        exit 1
        ;;
esac