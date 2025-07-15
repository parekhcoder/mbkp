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
    
    mongo_user=$(jq -r '.fields[] | select(.label=="user") | .value' <<< "$mongo_item")
    mongo_password=$(jq -r '.fields[] | select(.label=="pass") | .value' <<< "$mongo_item")
    mongo_host=$(jq -r '.fields[] | select(.label=="host") | .value' <<< "$mongo_item")
    mongo_port=$(jq -r '.fields[] | select(.label=="port") | .value' <<< "$mongo_item")
    mongo_auth_db=$(jq -r '.fields[] | select(.label=="authenticationDatabase") | .value' <<< "$mongo_item")
    mongo_config=$(jq -r '.fields[] | select(.label=="config") | .value' <<< "$mongo_item") # This will store the content of the config file

    if [[ -z "$mongo_user" || -z "$mongo_password" || -z "$mongo_host" || -z "$mongo_port" || -z "$mongo_auth_db" ]]; then
        log_msg "ERROR" "Missing fields in Mongo item (user, password, host, port, or authenticationDatabase)."
        return 1
    fi
    log_msg "DEBUG" "Mongo details retrieved."

    # Create mongodump config file for secure credentials
    mongo_cnf="$tmp_dir/mongo.cnf"
    cat > "$mongo_cnf" << EOF
username=$mongo_user
password=$mongo_password
host=$mongo_host
port=$mongo_port
authenticationDatabase=$mongo_auth_db
EOF
    # If a config field is provided, append its content to the mongo.cnf file
    if [[ -n "$mongo_config" ]]; then
        echo "$mongo_config" >> "$mongo_cnf"
    fi
    chmod 600 "$mongo_cnf" || {
        log_msg "ERROR" "Failed to set permissions on Mongo config file."
        return 1
    }

    # Verify Mongo connectivity (using mongosh or mongo client if available, else relying on mongodump itself)
    # For a simple connectivity check without `mongo` shell, we can try a basic `mongodump` dry run or `mongo` if installed.
    # Given the original script uses `mysql -e "SELECT 1"`, for MongoDB, a similar simple command with `mongosh` or `mongo` would be ideal.
    # However, if only `mongodump` is guaranteed, we'll rely on it failing later for connectivity issues.
    # A robust check would be:
    # if ! mongosh "mongodb://$mongo_user:$mongo_password@$mongo_host:$mongo_port/$mongo_auth_db" --eval "db.adminCommand('ping')" >/dev/null 2>&1; then
    #   log_msg "ERROR" "Failed to connect to MongoDB server."
    #   return 1
    # fi
    log_msg "DEBUG" "Vault items retrieved and S3 profiles configured."
    return 0
}

list_all_dbs_mongo() {
    log_msg "DEBUG" "Starting list_all_dbs_mongo function."
    local db_list
    if [[ "${TARGET_ALL_DATABASES:-false}" == "true" ]]; then
        if [[ -n "${TARGET_DATABASE_NAMES:-}" ]]; then
            log_msg "INFO" "TARGET_ALL_DATABASES is true; ignoring TARGET_DATABASE_NAMES for MongoDB."
            TARGET_DATABASE_NAMES=""
        fi
        
        # Use mongosh or mongo client to list databases.
        # This requires `mongosh` or `mongo` to be installed and accessible.
        # Ensure that mongo client is able to connect with the provided credentials.
        # Example using mongosh for listing databases (requires mongosh v1.0+):
        if ! command -v mongosh &>/dev/null; then
            log_msg "ERROR" "mongosh is not installed. Cannot list all databases dynamically."
            log_msg "ERROR" "Please set TARGET_DATABASE_NAMES explicitly or install mongosh."
            return 1
        fi

        local mongosh_cmd="mongosh \"mongodb://$mongo_user:$mongo_password@$mongo_host:$mongo_port/$mongo_auth_db\" --quiet --eval 'db.adminCommand({ listDatabases: 1, nameOnly: true }).databases.forEach(function(d){print(d.name)})'"
        log_msg "DEBUG" "Executing mongosh to list databases: $mongosh_cmd"

        if ! mapfile -t db_list < <(eval "$mongosh_cmd" 2>&1); then
            log_msg "ERROR" "Failed to list MongoDB databases."
            return 1
        fi

        # Exclude system databases like 'admin', 'config', 'local'
        local excluded_dbs=("admin" "config" "local")
        local filtered_db_list=()
        for db in "${db_list[@]}"; do
            local exclude=0
            for excluded_db in "${excluded_dbs[@]}"; do
                if [[ "$db" == "$excluded_db" ]]; then
                    exclude=1
                    break
                fi
            done
            if [[ "$exclude" -eq 0 ]]; then
                filtered_db_list+=("$db")
            fi
        done
        TARGET_DATABASE_NAMES=("${filtered_db_list[@]}")

        if [[ "${#TARGET_DATABASE_NAMES[@]}" -eq 0 ]]; then
            log_msg "WARN" "No user databases found to backup after exclusions."
        fi
        log_msg "DEBUG" "Built list of MongoDB databases: ${TARGET_DATABASE_NAMES[*]}"
    else
        if [[ -z "${TARGET_DATABASE_NAMES:-}" ]]; then
            log_msg "ERROR" "TARGET_DATABASE_NAMES is not set and TARGET_ALL_DATABASES is not true for MongoDB."
            return 1
        fi
        IFS=',' read -ra TARGET_DATABASE_NAMES <<< "${TARGET_DATABASE_NAMES}"
        if [[ "${#TARGET_DATABASE_NAMES[@]}" -eq 0 ]]; then
            log_msg "ERROR" "TARGET_DATABASE_NAMES is empty or contains only delimiters for MongoDB."
            return 1
        fi
        log_msg "DEBUG" "Target MongoDB databases specified: ${TARGET_DATABASE_NAMES[*]}"
    fi
    log_msg "DEBUG" "list_all_dbs_mongo function completed."
    return 0
}

backup_dbs_mongo() {
    log_msg "DEBUG" "Starting backup_dbs_mongo function."
    if [[ "${#TARGET_DATABASE_NAMES[@]}" -eq 0 ]]; then
        log_msg "WARN" "No databases specified or found to backup for MongoDB. Skipping backup process."
        return 0
    fi

    local overall_backup_status=0

    # Determine if we are backing up all databases or specific ones
    local mongodump_db_option=""
    if [[ "${TARGET_ALL_DATABASES:-false}" == "true" ]]; then
        log_msg "INFO" "Backing up all specified MongoDB databases."
        # When TARGET_ALL_DATABASES is true, TARGET_DATABASE_NAMES will contain specific DBs or be empty for literally "all"
        # mongodump without --db argument backs up all databases.
        # If TARGET_DATABASE_NAMES is populated, we will iterate and back up each one.
    else
        log_msg "INFO" "Backing up specific MongoDB databases: ${TARGET_DATABASE_NAMES[*]}"
    fi

    for db in "${TARGET_DATABASE_NAMES[@]}"; do
        log_msg "INFO" "Starting backup for MongoDB database: $db"
        local timestamp=$(date +${BACKUP_TIMESTAMP:-%Y%m%d%H%M%S})
        local backup_dir_name="mongodb_backup_${db}_${timestamp}"
        local dump_output_path="$tmp_dir/$backup_dir_name"
        local tmp_err_file="$tmp_dir/${db}_mongo_err.log"

        local mongodump_cmd="mongodump --config \"$mongo_cnf\" --db \"$db\" --out \"$dump_output_path\""

        if [[ -n "${BACKUP_ADDITIONAL_PARAMS:-}" ]]; then
            BACKUP_ADDITIONAL_PARAMS=$(echo "${BACKUP_ADDITIONAL_PARAMS}" | tr -s ' ' | sed 's/^ *//;s/ *$//')
            mongodump_cmd+=" $BACKUP_ADDITIONAL_PARAMS"
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

        if [[ ! -d "$dump_output_path/$db" ]]; then
            log_msg "ERROR" "Backup directory for $db is empty or invalid. Expected: $dump_output_path/$db"
            rm -rf "$dump_output_path"
            overall_backup_status=1
            continue
        fi

        local archive_file="$tmp_dir/${backup_dir_name}.tar.gz"
        local final_archive_name="${backup_dir_name}.tar.gz"

        if [[ "${BACKUP_COMPRESS:-false}" == "true" ]]; then
            log_msg "DEBUG" "Compressing $db MongoDB backup directory..."
            local level="${BACKUP_COMPRESS_LEVEL:-6}"
            # Create a compressed tar archive of the backup directory
            if ! tar -czf "$archive_file" -C "$tmp_dir" "$backup_dir_name" 2>/dev/null; then
                log_msg "ERROR" "Tar compression failed for database: $db."
                rm -rf "$dump_output_path" "$archive_file"
                overall_backup_status=1
                continue
            fi
            log_msg "DEBUG" "Compression completed."
            rm -rf "$dump_output_path"
        else
            log_msg "ERROR" "Compression is mandatory for MongoDB backups for single file upload. Please set BACKUP_COMPRESS=true."
            rm -rf "$dump_output_path"
            overall_backup_status=1
            continue
        fi
        
        local file_to_upload="$archive_file"
        local final_file_name="$final_archive_name"

        if [[ "${AGE_ENCRYPT:-false}" == "true" ]]; then
            log_msg "DEBUG" "Encrypting $db MongoDB backup..."
            if [[ -z "${age_public_key:-}" ]]; then
                log_msg "ERROR" "Age public key not found for encryption. Skipping encryption for $db."
                rm -f "$file_to_upload"
                overall_backup_status=1
                continue
            fi
            if ! age -a -r "$age_public_key" < "$file_to_upload" > "$file_to_upload.age"; then
                log_msg "ERROR" "Age encryption failed for database: $db."
                rm -f "$file_to_upload" "$file_to_upload.age"
                overall_backup_status=1
                continue
            fi
            log_msg "DEBUG" "Age encryption completed."
            rm -f "$file_to_upload"
            file_to_upload="$file_to_upload.age"
            final_file_name="$final_file_name.age"
        fi

        local cdate cyear cmonth
        cdate=$(date -u)
        cyear=$(date --date="$cdate" +%Y)
        cmonth=$(date --date="$cdate" +%m)

        if [[ "${CLOUD_UPLOAD:-false}" == "true" ]]; then
            log_msg "DEBUG" "Uploading $db backup to cloud S3..."
            local s3_error
            s3_error=$(aws --endpoint-url="$cloud_s3_url" \
                s3 cp "$file_to_upload" "s3://$cloud_s3_bucket$cloud_s3_bucket_path/$cyear/$cmonth/$final_file_name" \
                --profile cloud 2>&1)
            aws_exit_status=$?
            if [[ $aws_exit_status -ne 0 ]]; then
                log_msg "ERROR" "Cloud S3 upload failed for database: $db. Error: $s3_error"
                overall_backup_status=1
            else
                log_msg "INFO" "Cloud upload completed for $db: $cloud_s3_bucket$cloud_s3_bucket_path/$cyear/$cmonth/$final_file_name Output: $s3_error"
            fi
        fi        

        if [[ "${LOCAL_UPLOAD:-false}" == "true" ]]; then
            log_msg "DEBUG" "Uploading $db backup to local S3..."
            if [[ "${CLOUD_UPLOAD:-false}" == "true" && "$cloud_s3_url" == "$local_s3_url" && \
                "$cloud_s3_bucket" == "$local_s3_bucket" && "$cloud_s3_bucket_path" == "$local_s3_bucket_path" ]]; then
                log_msg "DEBUG" "Local and cloud S3 destinations are identical; skipping duplicate upload for $db."
            else
                local s3_error aws_exit_status original_sig_version
                
                original_sig_version=$(aws configure get s3.signature_version --profile local || echo "s4")
                
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
                    log_msg "ERROR" "Local S3 upload failed for database: $db. Error: $s3_error"
                    overall_backup_status=1
                else
                    log_msg "INFO" "Local upload completed for $db: $local_s3_bucket$local_s3_bucket_path/$cyear/$cmonth/$final_file_name Output: $s3_error"
                fi
            fi
        fi
        rm -f "$file_to_upload"
        log_msg "INFO" "Finished processing database: $db"
    done

    log_msg "DEBUG" "Backup process completed."
    return "$overall_backup_status"
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
        log_msg "ERROR" "Vault/S3 configuration failed."
        overall_script_status=1
    fi

    if [[ "$overall_script_status" -eq 0 ]]; then
        log_msg "DEBUG" "Calling list_all_dbs_mongo..."
        list_all_dbs_mongo
        status=$?
        log_msg "DEBUG" "list_all_dbs_mongo completed with status: $status"
        if [[ "$status" -ne 0 ]]; then
            log_msg "ERROR" "Listing MongoDB databases failed."
            overall_script_status=1
        fi
    else
        log_msg "WARN" "Skipping list_all_dbs_mongo due to previous failure."
    fi

    if [[ "$overall_script_status" -eq 0 || "${#TARGET_DATABASE_NAMES[@]}" -gt 0 ]]; then
        log_msg "DEBUG" "Calling backup_dbs_mongo..."
        backup_dbs_mongo
        status=$?
        log_msg "DEBUG" "backup_dbs_mongo completed with status: $status"
        if [[ "$status" -ne 0 ]]; then
            log_msg "WARN" "One or more MongoDB database backups failed."
            overall_script_status=1
        fi
    else
        log_msg "WARN" "Skipping backup_dbs_mongo as no databases were found or specified."
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
