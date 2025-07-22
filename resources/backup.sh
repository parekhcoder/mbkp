#!/bin/bash

set -uo pipefail
IFS=$'\n\t'

# Check required tools
for tool in jq aws mongodump gzip age curl sleep tee sync; do
    if ! command -v "$tool" &>/dev/null; then
        echo "ERROR: $tool is not installed." >&2
        exit 1
    fi
done

# Define default log directory early
LOG_DIR_PATH="${LOG_DIR:-/app/log}"

# Logging function with standardized levels and sync
log_msg() {
    local timestamp level message json_log
    
    level="$1"
    message="$2"
    
    timestamp=$(date -u '+%Y-%m-%dT%H:%M:%S.%NZ')    
    
    if ! json_log=$(jq -n -c \
        --arg t "$timestamp" \
        --arg a "$app_name" \
        --arg l "$level" \
        --arg m "$message" \
        --arg n "$node_name" \
        --arg p "$pod_name" \
        --arg T "$tenant" \
        '{"timestamp": $t, "appname": $a, "level": $l, "message": $m, "nodename": $n, "podname": $p, "tenant": $T}'
    ); then
        # Fallback if jq fails
        echo "ERROR: Failed to generate JSON log. Level: \"$level\", Message: \"$message\"" >&2        
    fi
    
    if [[ -z "${log_file:-}" || ! -w "$LOG_DIR_PATH" ]]; then        
        echo "$json_log"
    else
        echo "$json_log" | tee -a "$log_file"
        sync "$log_file" 2>/dev/null || echo "WARN: Failed to sync log file: $log_file" >&2
    fi    
}

# Trap for cleanup with logging
cleanup_tmp() {
    log_msg "DEBUG" "Running cleanup trap."
    local tmp_dir="/tmp/backup_$$"
    if ! rm -rf "$tmp_dir" 2>/dev/null; then
        log_msg "WARN" "Failed to clean up temporary directory: $tmp_dir"
    fi
    log_msg "DEBUG" "Cleanup trap finished."
}
trap cleanup_tmp EXIT

# Create private temporary directory
tmp_dir="/tmp/backup_$$"
mkdir -p "$tmp_dir" && chmod 700 "$tmp_dir" || {
    log_msg "ERROR" "Failed to create private temporary directory: $tmp_dir"
    exit 1
}

# Validate required environment variables
validate_env_vars() {
    local required_vars=(
        "OPWD_URL"
        "OPWD_TOKEN"
        "OPWD_VAULT"
        "OPWD_MONGO_KEY"
    )
    [[ "${CLOUD_UPLOAD:-false}" == "true" ]] && required_vars+=("OPWD_CLOUD_KEY")
    [[ "${LOCAL_UPLOAD:-false}" == "true" ]] && required_vars+=("OPWD_LOCAL_KEY")
    [[ "${AGE_ENCRYPT:-false}" == "true" ]] && required_vars+=("AGE_PUBLIC_KEY")

    local missing_vars=()
    for var in "${required_vars[@]}"; do
        # Use eval to safely check if the variable is unset or empty
        if ! eval "[ -n \"\${$var+x}\" ]" || [ -z "$(eval echo "\${$var}")" ]; then
            missing_vars+=("$var")
        fi
    done

    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        log_msg "ERROR" "Missing or empty required environment variables: ${missing_vars[*]}"
        return 1
    fi
    return 0
}

configure_s3_profile() {
    local profile="$1" uuid="$2" vault_uuid="$3"
    local item http_code access_key secret_key url bucket bucket_path

    item=$(curl -s -w "\n%{response_code}\n" "$OPWD_URL/v1/vaults/$vault_uuid/items/$uuid" \
        -H "Accept: application/json" -H "Authorization: Bearer $OPWD_TOKEN")
    http_code=$(tail -n1 <<< "$item")
    item=$(sed '$ d' <<< "$item")

    if [[ "$http_code" != "200" ]]; then
        case "$http_code" in
            401) log_msg "ERROR" "Unauthorized access to vault for $profile S3 item: $http_code" ;;
            404) log_msg "ERROR" "Vault item not found for $profile S3: $http_code" ;;
            *) log_msg "ERROR" "Failed to retrieve $profile S3 item: $http_code" ;;
        esac
        return 1
    fi

    access_key=$(jq -r '.fields[] | select(.label=="accesskey") | .value' <<< "$item")
    secret_key=$(jq -r '.fields[] | select(.label=="secretkey") | .value' <<< "$item")
    url=$(jq -r '.urls[0].href' <<< "$item")
    bucket=$(jq -r '.fields[] | select(.label=="bucket") | .value' <<< "$item")
    bucket_path=$(jq -r '.fields[] | select(.label=="mongodbbucketpath") | .value' <<< "$item")

    if [[ -z "$access_key" || -z "$secret_key" || -z "$url" || -z "$bucket" || -z "$bucket_path" ]]; then
        log_msg "ERROR" "Missing fields in $profile S3 item."
        return 1
    fi

    aws configure set aws_access_key_id "$access_key" --profile "$profile" || {
        log_msg "ERROR" "Failed to configure $profile aws access key id."
        return 1
    }
    aws configure set aws_secret_access_key "$secret_key" --profile "$profile" || {
        log_msg "ERROR" "Failed to configure $profile aws secret access key."
        return 1
    }
    
    case "$profile" in
        cloud)
            cloud_s3_url="$url"
            cloud_s3_bucket="$bucket"
            cloud_s3_bucket_path="$bucket_path"
            ;;
        local)
            local_s3_url="$url"
            local_s3_bucket="$bucket"
            local_s3_bucket_path="$bucket_path"
            ;;
    esac

    log_msg "DEBUG" "$profile S3 profile configured."
    return 0
}

get_vault_items_n_set_s3_profiles() {
    log_msg "DEBUG" "Starting get_vault_items_n_set_s3_profiles function."
    local vaults http_code vault_uuid vault_items cloud_s3_uuid local_s3_uuid mongo_uuid age_public_key_uuid

    vaults=$(curl -s -w "\n%{response_code}\n" "$OPWD_URL/v1/vaults" \
        -H "Accept: application/json" -H "Authorization: Bearer $OPWD_TOKEN")
    http_code=$(tail -n1 <<< "$vaults")
    vaults=$(sed '$ d' <<< "$vaults")
    if [[ "$http_code" != "200" ]]; then
        case "$http_code" in
            401) log_msg "ERROR" "Unauthorized access to vault: $http_code" ;;
            404) log_msg "ERROR" "Vault not found: $http_code" ;;
            *) log_msg "ERROR" "Failed to retrieve vaults: $http_code" ;;
        esac
        return 1
    fi
    log_msg "DEBUG" "Got vault list successfully."

    vault_uuid=$(jq -r '.[] | select(.name=="'"$OPWD_VAULT"'") | .id' <<< "$vaults")
    if [[ -z "$vault_uuid" ]]; then
        log_msg "ERROR" "Vault UUID not found for vault name: $OPWD_VAULT"
        return 1
    fi
    log_msg "DEBUG" "Found vault UUID: $vault_uuid"

    vault_items=$(curl -s -w "\n%{response_code}\n" "$OPWD_URL/v1/vaults/$vault_uuid/items" \
        -H "Accept: application/json" -H "Authorization: Bearer $OPWD_TOKEN")
    http_code=$(tail -n1 <<< "$vault_items")
    vault_items=$(sed '$ d' <<< "$vault_items")
    if [[ "$http_code" != "200" ]]; then
        case "$http_code" in
            401) log_msg "ERROR" "Unauthorized access to vault items: $http_code" ;;
            404) log_msg "ERROR" "Vault items not found: $http_code" ;;
            *) log_msg "ERROR" "Failed to retrieve vault items: $http_code" ;;
        esac
        return 1
    fi
    log_msg "DEBUG" "Got vault items list successfully."

    cloud_s3_uuid=$(jq -r '.[] | select(.title=="'"${OPWD_CLOUD_KEY:-}"'") | .id' <<< "$vault_items")
    local_s3_uuid=$(jq -r '.[] | select(.title=="'"${OPWD_LOCAL_KEY:-}"'") | .id' <<< "$vault_items")
    mongo_uuid=$(jq -r '.[] | select(.title=="'"${OPWD_MONGO_KEY:-}"'") | .id' <<< "$vault_items")
    age_public_key_uuid=$(jq -r '.[] | select(.title=="'"${AGE_PUBLIC_KEY:-}"'") | .id' <<< "$vault_items")

    if [[ "${CLOUD_UPLOAD:-false}" == "true" && -z "$cloud_s3_uuid" ]]; then
        log_msg "ERROR" "Cloud S3 key '${OPWD_CLOUD_KEY:-}' not found in vault items."
        return 1
    fi
    if [[ "${LOCAL_UPLOAD:-false}" == "true" && -z "$local_s3_uuid" ]]; then
        log_msg "ERROR" "Local S3 key '${OPWD_LOCAL_KEY:-}' not found in vault items."
        return 1
    fi
    if [[ -z "$mongo_uuid" ]]; then
        log_msg "ERROR" "Mongo key '${OPWD_MONGO_KEY:-}' not found in vault items."
        return 1
    fi
    if [[ "${AGE_ENCRYPT:-false}" == "true" && -z "$age_public_key_uuid" ]]; then
        log_msg "ERROR" "Age public key '${AGE_PUBLIC_KEY:-}' not found in vault items."
        return 1
    fi

    log_msg "DEBUG" "Item UUIDs found."

    if [[ "${CLOUD_UPLOAD:-false}" == "true" ]]; then
        configure_s3_profile "cloud" "$cloud_s3_uuid" "$vault_uuid" || return 1
    fi

    if [[ "${LOCAL_UPLOAD:-false}" == "true" ]]; then
        configure_s3_profile "local" "$local_s3_uuid" "$vault_uuid" || return 1
    fi

    if [[ "${AGE_ENCRYPT:-false}" == "true" ]]; then
        local age_public_key_item http_code
        age_public_key_item=$(curl -s -w "\n%{response_code}\n" "$OPWD_URL/v1/vaults/$vault_uuid/items/$age_public_key_uuid" \
            -H "Accept: application/json" -H "Authorization: Bearer $OPWD_TOKEN")
        http_code=$(tail -n1 <<< "$age_public_key_item")
        age_public_key_item=$(sed '$ d' <<< "$age_public_key_item")
        if [[ "$http_code" != "200" ]]; then
            case "$http_code" in
                401) log_msg "ERROR" "Unauthorized access to age public key: $http_code" ;;
                404) log_msg "ERROR" "Age public key item not found: $http_code" ;;
                *) log_msg "ERROR" "Failed to retrieve age public key: $http_code" ;;
            esac
            return 1
        fi
        age_public_key=$(jq -r '.fields[] | select(.id=="credential") | .value' <<< "$age_public_key_item")
        if [[ -z "$age_public_key" ]]; then
            log_msg "ERROR" "Missing public key field in age public key item."
            return 1
        fi
        log_msg "DEBUG" "Age public key retrieved."
    fi

    local mongo_item http_code
    mongo_item=$(curl -s -w "\n%{response_code}\n" "$OPWD_URL/v1/vaults/$vault_uuid/items/$mongo_uuid" \
        -H "Accept: application/json" -H "Authorization: Bearer $OPWD_TOKEN")
    http_code=$(tail -n1 <<< "$mongo_item")
    mongo_item=$(sed '$ d' <<< "$mongo_item")
    if [[ "$http_code" != "200" ]]; then
        case "$http_code" in
            401) log_msg "ERROR" "Unauthorized access to Mongo item: $http_code" ;;
            404) log_msg "ERROR" "Mongo item not found: $http_code" ;;
            *) log_msg "ERROR" "Failed to retrieve Mongo item: $http_code" ;;
        esac
        return 1
    fi
    
    mongo_uri=$(jq -r '.urls[0].href' <<< "$mongo_item") 
    mongo_user=$(jq -r '.fields[] | select(.label=="user") | .value' <<< "$mongo_item")
    mongo_password=$(jq -r '.fields[] | select(.label=="pass") | .value' <<< "$mongo_item")
    mongo_auth_db=$(jq -r '.fields[] | select(.label=="authenticationDatabase") | .value' <<< "$mongo_item")
    mongo_cnf=$(jq -r '.fields[] | select(.label=="config") | .value' <<< "$mongo_item")
    echo "$mongo_cnf" > mongoConfig.conf

    if [[ -z "$mongo_uri" || -z "$mongo_user" || -z "$mongo_password" || -z "$mongo_auth_db" ]]; then
        log_msg "ERROR" "Missing fields in Mongo item (URI, user, password, or authenticationDatabase)."
        return 1
    fi
    log_msg "DEBUG" "Mongo details retrieved."    
    
    if [[ -n "$mongo_config_extra" ]]; then
        echo "$mongo_config_extra" >> "$mongo_cnf"
    fi
    chmod 600 "$mongo_cnf" || {
        log_msg "ERROR" "Failed to set permissions on Mongo config file."
        return 1
    }

    log_msg "DEBUG" "Vault items retrieved and S3 profiles configured."
    return 0
}

# Function to get a list of all databases from MongoDB (excluding or including system dbs)
list_all_dbs_mongo() {
    log_msg "DEBUG" "Starting list_all_dbs_mongo function."
    local db_list_raw db_list_filtered=()
    
    if ! command -v mongosh &>/dev/null; then
        log_msg "ERROR" "mongosh is not installed. Cannot list all databases dynamically."
        log_msg "ERROR" "Please set TARGET_DATABASE_NAMES or TARGET_DB_COLLECTION_PAIRS explicitly or install mongosh."
        return 1
    fi

    local mongosh_cmd="mongosh \"$mongo_uri\" --username \"$mongo_user\" --password \"$mongo_password\" --authenticationDatabase \"$mongo_auth_db\" --quiet --eval 'db.adminCommand({ listDatabases: 1, nameOnly: true }).databases.forEach(function(d){print(d.name)})'"
    log_msg "DEBUG" "Executing mongosh to list databases."

    if ! mapfile -t db_list_raw < <(eval "$mongosh_cmd" 2>&1); then
        log_msg "ERROR" "Failed to list MongoDB databases. Ensure mongosh can connect using the provided URI and credentials."
        log_msg "ERROR" "mongosh output: $(eval "$mongosh_cmd")" # Log the output for debugging
        return 1
    fi

    # Filter out system databases unless INCLUDE_SYSTEM_DATABASES is true
    if [[ "${INCLUDE_SYSTEM_DATABASES:-false}" != "true" ]]; then
        local excluded_dbs=("admin" "config" "local")
        for db in "${db_list_raw[@]}"; do
            local exclude=0
            for excluded_db in "${excluded_dbs[@]}"; do
                if [[ "$db" == "$excluded_db" ]]; then
                    exclude=1
                    break
                fi
            done
            if [[ "$exclude" -eq 0 ]]; then
                db_list_filtered+=("$db")
            fi
        done
        TARGET_DATABASE_NAMES=("${db_list_filtered[@]}")
        log_msg "DEBUG" "Filtered MongoDB databases (excluding system): ${TARGET_DATABASE_NAMES[*]}"
    else
        TARGET_DATABASE_NAMES=("${db_list_raw[@]}")
        log_msg "DEBUG" "Included all MongoDB databases (including system): ${TARGET_DATABASE_NAMES[*]}"
    fi

    if [[ "${#TARGET_DATABASE_NAMES[@]}" -eq 0 ]]; then
        log_msg "WARN" "No databases found to backup after (or without) exclusions."
    fi
    log_msg "DEBUG" "list_all_dbs_mongo function completed."
    return 0
}


backup_dbs_mongo() {
    log_msg "DEBUG" "Starting backup_dbs_mongo function."
    local overall_backup_status=0
    local timestamp db_backup_name dump_output_path tmp_err_file mongodump_cmd mongodump_cmd_base

    # Build the base mongodump command with --config, --username, --authenticationDatabase
    # These parameters are common to all mongodump calls and are not part of the config file.
    mongodump_cmd_base="mongodump --config mongoConfig.conf --username \"$mongo_user\" --authenticationDatabase \"$mongo_auth_db\""

    # Add any additional parameters passed via environment variable
    if [[ -n "${BACKUP_ADDITIONAL_PARAMS:-}" ]]; then
        mongodump_cmd_base+=" ${BACKUP_ADDITIONAL_PARAMS}"
    fi

    # Priority 1: Specific collection backups
    if [[ -n "${TARGET_DB_COLLECTION_PAIRS:-}" ]]; then
        log_msg "INFO" "Performing collection-level MongoDB backups based on TARGET_DB_COLLECTION_PAIRS."
        IFS=',' read -ra db_collection_pairs_array <<< "${TARGET_DB_COLLECTION_PAIRS}"
        if [[ "${#db_collection_pairs_array[@]}" -eq 0 ]]; then
            log_msg "ERROR" "TARGET_DB_COLLECTION_PAIRS is empty or contains only delimiters."
            return 1
        fi

        for pair in "${db_collection_pairs_array[@]}"; do
            local db_name=$(echo "$pair" | cut -d':' -f1)
            local collection_name=$(echo "$pair" | cut -d':' -f2)

            if [[ -z "$db_name" || -z "$collection_name" ]]; then
                log_msg "ERROR" "Invalid DB:Collection pair: '$pair'. Skipping."
                overall_backup_status=1
                continue
            fi

            log_msg "INFO" "Starting backup for MongoDB database: '$db_name', collection: '$collection_name'"
            timestamp=$(date +${BACKUP_TIMESTAMP:-%Y%m%d%H%M%S})
            db_backup_name="mongodb_backup_${db_name}_${collection_name}_${timestamp}"
            dump_output_path="$tmp_dir/$db_backup_name"
            tmp_err_file="$tmp_dir/${db_name}_${collection_name}_mongo_err.log"

            mongodump_cmd="${mongodump_cmd_base} --db \"$db_name\" --collection \"$collection_name\" --out \"$dump_output_path\""
            if [[ -n "${BACKUP_ADDITIONAL_PARAMS:-}" ]]; then
                mongodump_cmd+=" ${BACKUP_ADDITIONAL_PARAMS}"
            fi

            log_msg "DEBUG" "Running mongodump command for '$db_name':'$collection_name': $mongodump_cmd"
            if ! eval "$mongodump_cmd" 2> >(tee "$tmp_err_file" >&2); then
                log_msg "ERROR" "mongodump failed for database: '$db_name', collection: '$collection_name'. Error: $(cat "$tmp_err_file" | head -n 1)"
                rm -rf "$dump_output_path" "$tmp_err_file"
                overall_backup_status=1
                continue
            fi
            rm -f "$tmp_err_file"
            log_msg "DEBUG" "MongoDB collection backup created at $dump_output_path"

            if ! process_mongo_backup_file "$dump_output_path" "$db_backup_name" "${db_name}_${collection_name}" ; then
                 overall_backup_status=1
            fi
        done

    # Priority 2: Full database backup (all databases, or filtered user dbs)
    elif [[ "${TARGET_ALL_DATABASES:-false}" == "true" ]]; then
        if [[ "${INCLUDE_SYSTEM_DATABASES:-false}" == "true" ]]; then
            log_msg "INFO" "Performing full MongoDB backup (all databases including system) as TARGET_ALL_DATABASES=true and INCLUDE_SYSTEM_DATABASES=true."
            timestamp=$(date +${BACKUP_TIMESTAMP:-%Y%m%d%H%M%S})
            db_backup_name="mongodb_backup_full_${timestamp}"
            dump_output_path="$tmp_dir/$db_backup_name"
            tmp_err_file="$tmp_dir/mongo_full_err.log"

            # No --db or --collection for a full dump
            mongodump_cmd="${mongodump_cmd_base} --out \"$dump_output_path\""
            if [[ -n "${BACKUP_ADDITIONAL_PARAMS:-}" ]]; then
                mongodump_cmd+=" ${BACKUP_ADDITIONAL_PARAMS}"
            fi

            log_msg "DEBUG" "Running mongodump command for full backup: $mongodump_cmd"
            if ! eval "$mongodump_cmd" 2> >(tee "$tmp_err_file" >&2); then
                log_msg "ERROR" "mongodump failed for full backup. Error: $(cat "$tmp_err_file" | head -n 1)"
                rm -rf "$dump_output_path" "$tmp_err_file"
                overall_backup_status=1
            else
                rm -f "$tmp_err_file"
                log_msg "DEBUG" "MongoDB full backup created at $dump_output_path"
                if ! process_mongo_backup_file "$dump_output_path" "$db_backup_name" "full_database_dump"; then
                    overall_backup_status=1
                fi
            fi
        else # TARGET_ALL_DATABASES=true but INCLUDE_SYSTEM_DATABASES is false/unset
            log_msg "INFO" "Performing all user MongoDB databases backup based on TARGET_ALL_DATABASES=true."
            # TARGET_DATABASE_NAMES will be populated by list_all_dbs_mongo, filtered for user dbs
            if [[ "${#TARGET_DATABASE_NAMES[@]}" -eq 0 ]]; then
                log_msg "WARN" "No user databases found to backup. Skipping database-level backup."
                return 0
            fi

            for db in "${TARGET_DATABASE_NAMES[@]}"; do
                log_msg "INFO" "Starting backup for MongoDB database: $db"
                timestamp=$(date +${BACKUP_TIMESTAMP:-%Y%m%d%H%M%S})
                db_backup_name="mongodb_backup_${db}_${timestamp}"
                dump_output_path="$tmp_dir/$db_backup_name"
                tmp_err_file="$tmp_dir/${db}_mongo_err.log"

                mongodump_cmd="${mongodump_cmd_base} --db \"$db\" --out \"$dump_output_path\""
                if [[ -n "${BACKUP_ADDITIONAL_PARAMS:-}" ]]; then
                    mongodump_cmd+=" ${BACKUP_ADDITIONAL_PARAMS}"
                fi

                log_msg "DEBUG" "Running mongodump command for $db: $mongodump_cmd"
                if ! eval "$mongodump_cmd" 2> >(tee "$tmp_err_file" >&2); then
                    log_msg "ERROR" "mongodump failed for database: $db. Error: $(cat "$tmp_err_file" | head -n 1)"
                    rm -rf "$dump_output_path" "$tmp_err_file"
                    overall_backup_status=1
                    continue
                fi
                rm -f "$tmp_err_file"
                log_msg "DEBUG" "MongoDB database backup created at $dump_output_path"

                if ! process_mongo_backup_file "$dump_output_path" "$db_backup_name" "$db" ; then
                    overall_backup_status=1
                fi
            done
        fi

    # Priority 3: Specific database backups
    elif [[ -n "${TARGET_DATABASE_NAMES:-}" ]]; then
        log_msg "INFO" "Performing specific MongoDB database backups based on TARGET_DATABASE_NAMES."
        IFS=',' read -ra TARGET_DATABASE_NAMES_ARRAY <<< "${TARGET_DATABASE_NAMES}"
        if [[ "${#TARGET_DATABASE_NAMES_ARRAY[@]}" -eq 0 ]]; then
            log_msg "ERROR" "TARGET_DATABASE_NAMES is empty or contains only delimiters for MongoDB."
            return 1
        fi

        for db in "${TARGET_DATABASE_NAMES_ARRAY[@]}"; do
            log_msg "INFO" "Starting backup for MongoDB database: $db"
            timestamp=$(date +${BACKUP_TIMESTAMP:-%Y%m%d%H%M%S})
            db_backup_name="mongodb_backup_${db}_${timestamp}"
            dump_output_path="$tmp_dir/$db_backup_name"
            tmp_err_file="$tmp_dir/${db}_mongo_err.log"

            mongodump_cmd="mongodump --config \"$mongo_cnf\" --db \"$db\" --out \"$dump_output_path\""
            if [[ -n "${BACKUP_ADDITIONAL_PARAMS:-}" ]]; then
                mongodump_cmd+=" ${BACKUP_ADDITIONAL_PARAMS}"
            fi

            log_msg "DEBUG" "Running mongodump command for $db: $mongodump_cmd"
            if ! eval "$mongodump_cmd" 2> >(tee "$tmp_err_file" >&2); then
                log_msg "ERROR" "mongodump failed for database: $db. Error: $(cat "$tmp_err_file" | head -n 1)"
                rm -rf "$dump_output_path" "$tmp_err_file"
                overall_backup_status=1
                continue
            fi
            rm -f "$tmp_err_file"
            log_msg "DEBUG" "MongoDB database backup created at $dump_output_path"

            if ! process_mongo_backup_file "$dump_output_path" "$db_backup_name" "$db" ; then
                overall_backup_status=1
            fi
        done
    else
        log_msg "ERROR" "No MongoDB backup targets specified. Please set TARGET_DB_COLLECTION_PAIRS, TARGET_ALL_DATABASES, or TARGET_DATABASE_NAMES."
        return 1
    fi

    log_msg "DEBUG" "Backup process completed."
    return "$overall_backup_status"
}

# New helper function to process a single MongoDB backup directory (compress, encrypt, upload)
process_mongo_backup_file() {
    local dump_output_path="$1"
    local backup_dir_name="$2"
    local identifier="$3" # e.g., actual db name or "full_database_dump" or "db_collection"

    local archive_file="$tmp_dir/${backup_dir_name}.tar.gz"
    local final_archive_name="${backup_dir_name}.tar.gz"

    if [[ "${BACKUP_COMPRESS:-false}" == "true" ]]; then
        log_msg "DEBUG" "Compressing '$identifier' MongoDB backup directory..."
        local level="${BACKUP_COMPRESS_LEVEL:-6}"
        # Create a compressed tar archive of the backup directory
        if ! tar -czf "$archive_file" -C "$tmp_dir" "$backup_dir_name" 2>/dev/null; then
            log_msg "ERROR" "Tar compression failed for backup: '$identifier'."
            rm -rf "$dump_output_path" "$archive_file"
            return 1
        fi
        log_msg "DEBUG" "Compression completed."
        rm -rf "$dump_output_path" # Clean up uncompressed dump
    else
        # For MongoDB, mongodump creates a directory structure, which is not ideal for direct S3 upload of a single object.
        # Compression into a single tar.gz file is almost always desired.
        log_msg "ERROR" "Compression is mandatory for MongoDB backups for single file upload. Please set BACKUP_COMPRESS=true."
        rm -rf "$dump_output_path"
        return 1
    fi
    
    local file_to_upload="$archive_file"
    local final_file_name="$final_archive_name"

    if [[ "${AGE_ENCRYPT:-false}" == "true" ]]; then
        log_msg "DEBUG" "Encrypting '$identifier' MongoDB backup..."
        if [[ -z "${age_public_key:-}" ]]; then
            log_msg "ERROR" "Age public key not found for encryption. Skipping encryption for '$identifier'."
            rm -f "$file_to_upload"
            return 1
        fi
        if ! age -a -r "$age_public_key" < "$file_to_upload" > "$file_to_upload.age"; then
            log_msg "ERROR" "Age encryption failed for backup: '$identifier'."
            rm -f "$file_to_upload" "$file_to_upload.age"
            return 1
        fi
        log_msg "DEBUG" "Age encryption completed."
        rm -f "$file_to_upload" # Remove unencrypted archive
        file_to_upload="$file_to_upload.age"
        final_file_name="$final_file_name.age"
    fi

    local cdate cyear cmonth
    cdate=$(date -u)
    cyear=$(date --date="$cdate" +%Y)
    cmonth=$(date --date="$cdate" +%m)

    if [[ "${CLOUD_UPLOAD:-false}" == "true" ]]; then
        log_msg "DEBUG" "Uploading '$identifier' backup to cloud S3..."
        local s3_error
        s3_error=$(aws --endpoint-url="$cloud_s3_url" \
            s3 cp "$file_to_upload" "s3://$cloud_s3_bucket$cloud_s3_bucket_path/$cyear/$cmonth/$final_file_name" \
            --profile cloud 2>&1)
        aws_exit_status=$?
        if [[ $aws_exit_status -ne 0 ]]; then
            log_msg "ERROR" "Cloud S3 upload failed for backup: '$identifier'. Error: $s3_error"
            rm -f "$file_to_upload" # Clean up even on upload fail for cloud
            return 1
        else
            log_msg "INFO" "Cloud upload completed for '$identifier': s3://$cloud_s3_bucket$cloud_s3_bucket_path/$cyear/$cmonth/$final_file_name Output: $s3_error"
        fi
    fi        

    if [[ "${LOCAL_UPLOAD:-false}" == "true" ]]; then
        log_msg "DEBUG" "Uploading '$identifier' backup to local S3..."
        if [[ "${CLOUD_UPLOAD:-false}" == "true" && "$cloud_s3_url" == "$local_s3_url" && \
            "$cloud_s3_bucket" == "$local_s3_bucket" && "$cloud_s3_bucket_path" == "$local_s3_bucket_path" ]]; then
            log_msg "DEBUG" "Local and cloud S3 destinations are identical; skipping duplicate upload for '$identifier'."
        else
            local s3_error aws_exit_status original_sig_version
            
            original_sig_version=$(aws configure get s3.signature_version --profile local || echo "s4") # Default to s4 if not set
            
            if [[ "${LOCAL_S3_SIGNATURE_VERSION:-s4}" == "s3" ]]; then
                aws configure set s3.signature_version s3 --profile local
                log_msg "DEBUG" "Set Signature Version 2 for local S3 upload (endpoint: $local_s3_url)"
            else
                log_msg "DEBUG" "Using Signature Version 4 for local S3 upload (endpoint: $local_s3_url)"
            fi
            
            s3_error=$(aws --endpoint-url="$local_s3_url" \
                s3 cp "$file_to_upload" "s3://$local_s3_bucket$local_s3_bucket_path/$cyear/$cmonth/$final_file_name" \
                --profile local 2>&1)
            aws_exit_status=$?
            if [[ $aws_exit_status -ne 0 ]]; then
                log_msg "ERROR" "Local S3 upload failed for backup: '$identifier'. Error: $s3_error"
                rm -f "$file_to_upload" # Clean up even on upload fail for local
                return 1
            else
                log_msg "INFO" "Local upload completed for '$identifier': s3://$local_s3_bucket$local_s3_bucket_path/$cyear/$cmonth/$final_file_name Output: $s3_error"
            fi
            
            # Restore original S3 signature version if it was changed
            if [[ "${LOCAL_S3_SIGNATURE_VERSION:-s4}" == "s3" && "$original_sig_version" != "s3" ]]; then
                aws configure set s3.signature_version "$original_sig_version" --profile local
                log_msg "DEBUG" "Restored original Signature Version: $original_sig_version for local S3 profile."
            fi
        fi
    fi
    rm -f "$file_to_upload" # Clean up after successful upload
    log_msg "INFO" "Finished processing backup for: '$identifier'"
    return 0
}

main() {

    validate_env_vars || {
        log_msg "FATAL" "Environment variable validation failed. Exiting."
        exit 1
    }

    mkdir -p "$LOG_DIR_PATH" || {
        log_msg "FATAL" "Failed to create log directory: $LOG_DIR_PATH"
        exit 1
    }
    chmod 700 "$LOG_DIR_PATH" || {
        log_msg "FATAL" "Failed to set permissions on log directory: $LOG_DIR_PATH"
        exit 1
    }
    if [[ ! -w "$LOG_DIR_PATH" ]]; then
        log_msg "FATAL" "Log directory is not writable: $LOG_DIR_PATH"
        exit 1
    fi

    local year month pod_name node_name
    year=$(date +%Y)
    month=$(date +%m)
    pod_name="${POD_NAME:-$(hostname)}"
    node_name="${NODE_NAME:-unknown}"
    app_name="${APP_NAME:-unknown}"    
    tenant="${TENANT:-unknown}"
    log_file="$LOG_DIR_PATH/${year}_${month}_${tenant}_${app_name}.log"    

    log_msg "INFO" "Script started. Log file: $log_file"

    
    if [ "$(date +%d)" = "01" ]; then
        log_msg "DEBUG" "Deleting old log files"    
        find "$LOG_DIR_PATH" -type f -name "*.log" -mtime +60 -exec rm -f {} \; || log_msg "Error" "Error while deleting old log files"
    fi

    local overall_script_status=0

    log_msg "DEBUG" "Calling get_vault_items_n_set_s3_profiles..."
    get_vault_items_n_set_s3_profiles
    local status=$?
    log_msg "DEBUG" "get_vault_items_n_set_s3_profiles completed with status: $status"
    if [[ "$status" -ne 0 ]]; then
        log_msg "ERROR" "Vault/S3 configuration failed. Exiting."
        exit 1 # Fatal error, cannot proceed without credentials
    fi

    # Determine backup strategy based on environment variables
    # Priority: TARGET_DB_COLLECTION_PAIRS > TARGET_ALL_DATABASES > TARGET_DATABASE_NAMES

    # If TARGET_DB_COLLECTION_PAIRS is set, no need to list databases
    if [[ -z "${TARGET_DB_COLLECTION_PAIRS:-}" ]]; then
        # If TARGET_ALL_DATABASES is true, we might need to list databases (unless doing a full dump)
        if [[ "${TARGET_ALL_DATABASES:-false}" == "true" && "${INCLUDE_SYSTEM_DATABASES:-false}" != "true" ]]; then
            log_msg "DEBUG" "Calling list_all_dbs_mongo to get user databases..."
            list_all_dbs_mongo
            status=$?
            log_msg "DEBUG" "list_all_dbs_mongo completed with status: $status"
            if [[ "$status" -ne 0 ]]; then
                log_msg "ERROR" "Listing MongoDB databases failed for 'all user databases' strategy. Exiting."
                exit 1 # Cannot proceed if we can't determine databases for this strategy
            fi
        fi
    else
        log_msg "INFO" "TARGET_DB_COLLECTION_PAIRS is set. Prioritizing collection-level backup. Ignoring other TARGET_* settings."
    fi

    log_msg "DEBUG" "Calling backup_dbs_mongo..."
    backup_dbs_mongo
    status=$?
    log_msg "DEBUG" "backup_dbs_mongo completed with status: $status"
    if [[ "$status" -ne 0 ]]; then
        log_msg "ERROR" "One or more MongoDB backups failed."
        overall_script_status=1
    fi

    log_msg "INFO" "Script finished main tasks."
    
    if [[ -n "${SCRIPT_POST_RUN_SLEEP_SECONDS:-}" && "${SCRIPT_POST_RUN_SLEEP_SECONDS}" =~ ^[0-9]+$ ]]; then
        if [[ "${SCRIPT_POST_RUN_SLEEP_SECONDS}" -gt 300 ]]; then
            log_msg "WARN" "SCRIPT_POST_RUN_SLEEP_SECONDS is set to ${SCRIPT_POST_RUN_SLEEP_SECONDS}s, which is unusually long."
        fi
        log_msg "INFO" "Sleeping for ${SCRIPT_POST_RUN_SLEEP_SECONDS} seconds to allow log processing."
        sleep "$SCRIPT_POST_RUN_SLEEP_SECONDS" || log_msg "WARN" "Sleep command interrupted or failed."
        log_msg "INFO" "Sleep completed."
    fi

    log_msg "INFO" "Script exiting with overall status: $overall_script_status"
    return "$overall_script_status"
}

main
status=$?
if [[ $status -ne 0 ]]; then
    log_msg "FATAL" "main function failed with status: $status"
    exit $status
fi
exit 0
