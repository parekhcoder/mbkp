# !/bin/bash
function SetS3Profiles()
{
    # Fetch vaults
    local vaults=$(curl -s -w "\n%{response_code}\n" $OPWD_URL/v1/vaults -H "Accept: application/json"  -H "Authorization: Bearer $OPWD_TOKEN")
    local http_code=$(tail -n1 <<< "$vaults")
    vaults=$(sed '$ d' <<< "$vaults")

    if [ "$http_code" != "200" ]; then
        echo "Error: Failed to retrieve vaults. HTTP code: $http_code"
        return 1
    fi

    echo "Got Vaults"

    # Extract Vault UUID
    local vaultUUID=$(jq -r '.[] | select(.name=="'$OPWD_VAULT'") | .id' <<< "$vaults")
    if [ -z "$vaultUUID" ]; then
        echo "Error: Vault '$OPWD_VAULT' not found."
        return 1
    fi
    echo "VaultID: $vaultUUID"

    # Fetch vault items
    local vaultItems=$(curl -s -w "\n%{response_code}\n" $OPWD_URL/v1/vaults/$vaultUUID/items -H "Accept: application/json"  -H "Authorization: Bearer $OPWD_TOKEN")
    http_code=$(tail -n1 <<< "$vaultItems")
    vaultItems=$(sed '$ d' <<< "$vaultItems")

    if [ "$http_code" != "200" ]; then
        echo "Error: Failed to retrieve vault items. HTTP code: $http_code"
        return 1
    fi

    echo "Got Vault Items"

    # Extract UUIDs for items
    local cloudS3UUID=$(jq -r '.[] | select(.title=="'$OPWD_CLOUD_KEY'") | .id' <<< "$vaultItems")
    local localS3UUID=$(jq -r '.[] | select(.title=="'$OPWD_LOCAL_KEY'") | .id' <<< "$vaultItems")
    local agePublicKeyUUID=$(jq -r '.[] | select(.title=="'$OPWD_AGE_KEY'") | .id' <<< "$vaultItems")
    local mongoUUID=$(jq -r '.[] | select(.title=="'$OPWD_MONGO_KEY'") | .id' <<< "$vaultItems")

    # Fetch cloud S3 item if CLOUD_UPLOAD is enabled
    if [ "$CLOUD_UPLOAD" = "true" ]; then
        if [ -z "$cloudS3UUID" ]; then
            echo "Error: Cloud S3 key '$OPWD_CLOUD_KEY' not found in vault items."
            return 1
        fi

        local cloudS3Item=$(curl -s -w "\n%{response_code}\n" $OPWD_URL/v1/vaults/$vaultUUID/items/$cloudS3UUID -H "Accept: application/json"  -H "Authorization: Bearer $OPWD_TOKEN")
        local httpCode=$(tail -n1 <<< "$cloudS3Item")
        cloudS3Item=$(sed '$ d' <<< "$cloudS3Item")

        if [ "$httpCode" != "200" ]; then
            echo "Error: Failed to retrieve cloud S3 item. HTTP code: $httpCode, Response: $cloudS3Item"
            return 1
        fi

        local cloudS3AccessKey=$(jq -r '.fields[] | select(.label=="accesskey") | .value' <<< "$cloudS3Item")
        local cloudS3SecretKey=$(jq -r '.fields[] | select(.label=="secretkey") | .value' <<< "$cloudS3Item")
        cloudS3URL=$(jq -r '.urls[0].href' <<< "$cloudS3Item")
        cloudS3Bucket=$(jq -r '.fields[] | select(.label=="bucket") | .value' <<< "$cloudS3Item")
        cloudS3BucketPath=$(jq -r '.fields[] | select(.label=="bucketpath") | .value' <<< "$cloudS3Item")

        # Configure AWS for cloud profile
        aws configure set aws_access_key_id "$cloudS3AccessKey" --profile cloud
        aws configure set aws_secret_access_key "$cloudS3SecretKey" --profile cloud
    fi

    # Fetch local S3 item if LOCAL_UPLOAD is enabled
    if [ "$LOCAL_UPLOAD" = "true" ]; then
        if [ -z "$localS3UUID" ]; then
            echo "Error: Local S3 key '$OPWD_LOCAL_KEY' not found in vault items."
            return 1
        fi

        local localS3Item=$(curl -s -w "\n%{response_code}\n" $OPWD_URL/v1/vaults/$vaultUUID/items/$localS3UUID -H "Accept: application/json"  -H "Authorization: Bearer $OPWD_TOKEN")
        local httpCode=$(tail -n1 <<< "$localS3Item")
        localS3Item=$(sed '$ d' <<< "$localS3Item")

        if [ "$httpCode" != "200" ]; then
            echo "Error: Failed to retrieve local S3 item. HTTP code: $httpCode, Response: $localS3Item"
            return 1
        fi

        local localS3AccessKey=$(jq -r '.fields[] | select(.label=="accesskey") | .value' <<< "$localS3Item")
        local localS3SecretKey=$(jq -r '.fields[] | select(.label=="secretkey") | .value' <<< "$localS3Item")
        localS3URL=$(jq -r '.urls[0].href' <<< "$localS3Item")
        localS3Bucket=$(jq -r '.fields[] | select(.label=="bucket") | .value' <<< "$localS3Item")
        localS3BucketPath=$(jq -r '.fields[] | select(.label=="bucketpath") | .value' <<< "$localS3Item")

        # Configure AWS for local profile
        aws configure set aws_access_key_id "$localS3AccessKey" --profile local
        aws configure set aws_secret_access_key "$localS3SecretKey" --profile local
    fi

    # Fetch the Age public key
    if [ -z "$agePublicKeyUUID" ]; then
        echo "Error: Age public key '$AGE_PUBLIC_KEY' not found in vault items."
        return 1
    fi

    local agePublicKeyItem=$(curl -s -w "\n%{response_code}\n" $OPWD_URL/v1/vaults/$vaultUUID/items/$agePublicKeyUUID -H "Accept: application/json"  -H "Authorization: Bearer $OPWD_TOKEN")
    local httpCode=$(tail -n1 <<< "$agePublicKeyItem")
    agePublicKeyItem=$(sed '$ d' <<< "$agePublicKeyItem")

    if [ "$httpCode" != "200" ]; then
        echo "Error: Failed to retrieve Age public key item. HTTP code: $httpCode, Response: $agePublicKeyItem"
        return 1
    fi

    agePublicKey=$(jq -r '.fields[] | select(.id=="credential") | .value' <<< "$agePublicKeyItem")
    echo "Age public key successfully retrieved."

    if [ -z "$mongoUUID" ]; then
            echo "Error: Mongo key '$OPWD_MONGO_KEY' not found in vault items."
            return 1
        fi

        local mongoItem=$(curl -s -w "\n%{response_code}\n" $OPWD_URL/v1/vaults/$vaultUUID/items/$mongoUUID -H "Accept: application/json"  -H "Authorization: Bearer $OPWD_TOKEN")
        local httpCode=$(tail -n1 <<< "$mongoItem")
        mongoItem=$(sed '$ d' <<< "$mongoItem")

        if [ "$httpCode" != "200" ]; then
            echo "Error: Failed to retrieve mongo item. HTTP code: $httpCode, Response: $mongoItem"
            return 1
        fi

        mongoUser=$(jq -r '.fields[] | select(.label=="user") | .value' <<< "$mongoItem")
       # mongoPwd=$(jq -r '.fields[] | select(.label=="pass") | .value' <<< "$mongoItem")
       # mongoHost=$(jq -r '.fields[] | select(.label=="host") | .value' <<< "$mongoItem")
       mongoConfig=$(jq -r '.fields[] | select(.label=="config") | .value' <<< "$mongoItem")
       echo "$mongoConfig" > mongoConfig.conf
}

function Backup()
{    # Check if Age recipient is provided
    if [ -z "$agePublicKey" ]; then
        echo "Error: Age recipient key is required for encryption."
        return 1
    fi

    # Create output directory if it doesn't exist
    mkdir -p "$OUTPUT_DIR"

    # Get current timestamp for the filename    
    local cdate=$(date -u)
    local cyear=$(date --date="$cdate" +%Y)
    local cmonth=$(date --date="$cdate" +%m)
    local timestamp=$(date --date="$cdate" +$BACKUP_TIMESTAMP)
    

    # Construct the mongodump command with conditional database and collection
    local dumpCMD="mongodump --config mongoConfig.conf --authenticationDatabase admin --username $mongoUser"
    local dbName="all"
    local colName="all"

    if [ -n "$DATABASE" ]; then
        dump_cmd+=" --db $database"
        $dbName=$database
    fi

    if [ -n "$COLLECTION" ]; then
        dump_cmd+=" --collection $collection"
        $colName=$collection
    fi

    
    if [ -n "$BACKUP_ADDITIONAL_PARAMS" ]; then
        dump_cmd+=" $BACKUP_ADDITIONAL_PARAMS"        
    fi

    # Output file for the backup
    local dumpDir="$OUTPUT_DIR/mongodb_backup_${dbName}_${colName}_${timestamp}"    
    dump_cmd+=" --out $dumpDir"
    # Run the mongodump command and save output
    $dumpCMD 
    if [ $? -ne 0 ]; then
        echo "Error: mongodump failed."
        return 1
    fi

     echo "Backup created in directory: $dumpDir"

      # Compress the backup directory using tar
    local tarFile="$dumpDir.tar.gz"
    tar -czf "$tarFile" "$dumpDir"
    if [ $? -ne 0 ]; then
        echo "Error: Tar compression failed."
        return 1
    fi

    echo "Backup compressed into: $tarFile"

    # Encrypt the backup file using Age
    local encryptedFile="${tarFile}.age"
    age -r "$agePublicKey" -o "$encryptedFile" "$tarFile"
    if [ $? -ne 0 ]; then
        echo "Error: Encryption failed."
        return 1
    fi

    # Remove the original unencrypted tar file
    #rm "$tarFile"

    echo "Encrypted backup created: $encryptedFile"

    if [ "$CLOUD_UPLOAD" = "true" ]; 
			then
				if awsOutput=$(aws --no-verify-ssl  --only-show-errors --endpoint-url=$cloudS3URL s3 cp $encryptedFile s3://$cloudS3Bucket$cloudS3BucketPath/$cyear/$cmonth/$fileName.age --profile cloud 2>&1); 
		  		      then
			  			echo "Success: Cloud Upload at $cloudS3Bucket$cloudS3BucketPath/$cyear/$cmonth/$fileName.age"
		                      else
		                        	isSuccess=false
						echo "Error: s3upload msg: $awsOutput"
		                fi
		fi
    
	      if [ "$LOCAL_UPLOAD" = "true" ]; 
		then
		      if awsOutput=$(aws --no-verify-ssl --only-show-errors --endpoint-url=$localS3URL s3 cp $encryptedFile s3://$localS3Bucket$localS3BucketPath/$cyear/$cmonth/$fileName.age --profile local 2>&1); 
			then
			 	  echo "Success: Local Upload at $localS3Bucket$localS3BucketPath/$cyear/$cmonth/$fileName.age"
			else
			  	isSuccess=false
      				echo "Error: Local Upload msg: $awsOutput"
		      fi
	      fi		
    
    echo "Backup process completed successfully."

    #rm "$tarFile".age

}

function Main()
{
    SetS3Profiles
    if [ $? -ne 0 ]; then
        echo "Error: Failed to set S3 profiles."
        return 1
    fi
	
	Backup
	 if [ $? -ne 0 ]; then
        echo "Error: Failed to set S3 profiles."
        return 1
    fi
}
Main
tail -f /dev/null
