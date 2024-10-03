#!/bin/bash
# Run this script from the host while the docker containers are up to save a database
# backup in the ${DATA_PATH}/backups directory.
# The backup is saved in a directory with the current date, the filename corresponds
# to the current time.

source .env

current_date=$(date +"%Y-%m-%d")

# make the directory if it doesn't exist already
backup_path="${DATA_PATH}/backups/${current_date}"
mkdir -p $backup_path

current_time=$(date +%H.%M.%S)
container_name=$(docker ps --format "{{.Names}}" | grep firmwarescraper-db)

docker exec $container_name pg_dump metadata >"${backup_path}/${current_time}.sql"

echo "Wrote backup to ${backup_path}/${current_time}.sql"
