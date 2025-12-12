#!/bin/bash

set -e


echo "Running auth migrations..."
sqlx migrate run --source ../migrations/auth --database-url sqlite://../auth.db

echo "Running files migrations..."
sqlx migrate run --source ../migrations/files --database-url sqlite://../files.db

echo "Preparing queries..."
cargo sqlx prepare --database-url sqlite:../auth.db

echo "Database setup complete!"
