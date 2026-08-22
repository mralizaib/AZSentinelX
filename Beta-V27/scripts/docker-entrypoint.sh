#!/bin/bash
set -e

# Run database initialization script
if [ -f /app/scripts/init_db.sh ]; then
  echo "Running database initialization script..."
  /app/scripts/init_db.sh
fi

# Execute the command passed to the container
echo "Starting the application..."
exec "$@"