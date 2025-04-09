FROM ubuntu:24.04

# Environment
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
        protobuf-compiler \
        libgtest-dev \
        libgflags-dev \
        protoc-gen-go \
        golang-go \
        libmbedtls-dev \
        software-properties-common \
        libssl-dev\
        uuid-dev\
        python3-pip\
        swig \
        git \
        nano \
        sudo \
        bash && \
    rm -rf /var/lib/apt/lists/*

# Copy files

# COPY start_certifier_service.sh /start_certifier_service.sh
COPY certifier-framework-for-confidential-computing/ /root/certifier-framework-for-confidential-computing/
COPY entrypoint.sh /root/entrypoint.sh
COPY start_certifier_service.sh /root/start_certifier_service.sh
COPY run_client.sh /root/run_client.sh
COPY run_server.sh /root/run_server.sh

# Make scripts executable
RUN chmod +x /root/entrypoint.sh
RUN chmod +x /root/start_certifier_service.sh
RUN chmod +x /root/run_client.sh
RUN chmod +x /root/run_server.sh

# RUN chmod +x /start_certifier_service.sh

# Install certifier-framework-for-confidential-computing dependencies

# Working directory
WORKDIR /root/certifier-framework-for-confidential-computing

# Entry point script
ENTRYPOINT ["/root/entrypoint.sh"]
