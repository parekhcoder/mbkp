# Set the base image
FROM ubuntu:22.04

RUN apt-get update \    
    apt-get install -y curl jq \       
    python3 \
    python3-pip \
    groff \
    less \
    mailcap \    
    curl \    
    python3-crcmod \    
    libc6 \
    gnupg \
    coreutils \
    gzip \      
    gcc make \
    golang \    
    git && \
    pip3 install --upgrade awscli s3cmd python-magic && \
    export PATH="/usr/lib/go/bin:$PATH"

RUN curl -O https://downloads.mongodb.com/compass/mongodb-mongosh_2.3.3_amd64.deb \
    apt install ./mongodb-mongosh_2.3.3_amd64.deb && \
    rm -f mongodb-mongosh_2.3.3_amd64.deb

    # Set Default Environment Variables
ENV BACKUP_CREATE_DATABASE_STATEMENT=false
ENV TARGET_DATABASE_PORT=3306
ENV SLACK_ENABLED=false
ENV SLACK_USERNAME=kubernetes-s3-mysql-backup
ENV CLOUD_SDK_VERSION=367.0.0
# Release commit for https://github.com/FiloSottile/age/tree/v1.0.0
ENV AGE_VERSION=552aa0a07de0b42c16126d3107bd8895184a69e7
ENV BACKUP_PROVIDER=aws

# Install FiloSottile/age (https://github.com/FiloSottile/age)
RUN git clone https://filippo.io/age && \
    cd age && \
    git checkout $AGE_VERSION && \
    go build -o . filippo.io/age/cmd/... && cp age /usr/local/bin/

# Set Google Cloud SDK Path
ENV PATH /google-cloud-sdk/bin:$PATH

# Install Google Cloud SDK
RUN curl -O https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-sdk-${CLOUD_SDK_VERSION}-linux-x86_64.tar.gz && \
    tar xzf google-cloud-sdk-${CLOUD_SDK_VERSION}-linux-x86_64.tar.gz && \
    rm google-cloud-sdk-${CLOUD_SDK_VERSION}-linux-x86_64.tar.gz && \
    gcloud config set core/disable_usage_reporting true && \
    gcloud config set component_manager/disable_update_check true && \
    gcloud config set metrics/environment github_docker_image && \
    gcloud --version

# Copy backup script and execute
COPY resources/backup.sh /
RUN chmod +x /backup.sh
CMD ["bash", "/backup.sh"]
