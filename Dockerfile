# Set the base image
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
# Path includes /usr/lib/go/bin and /root/.local/bin for age, awscli user binaries
ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/go/bin:/root/.local/bin:${PATH}"

# Set the working directory inside the container
WORKDIR /app

# Ensure /var/log/cron.log exists and is writable (best practice for cron)
# Also create /app/log for your script's logs
RUN mkdir -p /app/log && \
    touch /var/log/cron.log /app/log/cron.log && \
    chmod 644 /var/log/cron.log /app/log/cron.log

# Install packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        jq \
        python3 \
        python3-pip \
        groff \
        less \
        mailcap \
        python3-crcmod \
        gnupg \
        coreutils \
        gzip \
        gcc \
        make \
        golang \
        cron \
        git \
        wget \
        libc6 && \
    # Install Google Cloud SDK
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
    curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - && \
    apt-get update && \
    apt-get install -y google-cloud-sdk && \
    gcloud config set core/disable_usage_reporting true && \
    gcloud config set component_manager/disable_update_check true && \
    gcloud config set metrics/environment github_docker_image && \
    gcloud --version && \
    # Install MongoDB Database Tools
    wget -q https://fastdl.mongodb.org/tools/db/mongodb-database-tools-debian12-x86_64-100.10.0.deb -O /tmp/mongodb-database-tools.deb && \
    apt install -y /tmp/mongodb-database-tools.deb && \
    rm -f /tmp/mongodb-database-tools.deb && \
    # Clean up apt caches
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    # Install Python packages
    pip3 install --break-system-packages --no-cache-dir --upgrade awscli s3cmd python-magic

ENV CLOUD_SDK_VERSION=367.0.0 
# Release commit for https://github.com/FiloSottile/age/tree/v1.0.0
ENV AGE_VERSION=552aa0a07de0b42c16126d3107bd8895184a69e7
ENV BACKUP_PROVIDER=aws 

# Install FiloSottile/age (https://github.com/FiloSottile/age)
RUN git clone https://filippo.io/age && \
    cd age && \
    git checkout $AGE_VERSION && \
    go build -o . filippo.io/age/cmd/... && cp age /usr/local/bin/    

# Copy backup script and execute permissions
COPY resources/backup.sh /app/backup.sh
RUN chmod +x /app/backup.sh

COPY resources/setup_cron.sh /app/setup_cron.sh
RUN chmod +x /app/setup_cron.sh

# This creates the /app/log directory, where your script's main log file will reside.
# Ensure it's writable by the user running the cron job (usually root in Docker).
RUN chmod 777 /app/log

CMD ["/app/setup_cron.sh"]
