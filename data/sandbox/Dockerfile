FROM alpine:latest

# Basic tools for script execution
RUN apk add --no-cache bash python3 coreutils

# Create a non-privileged user
RUN addgroup -S sentinel && adduser -S sentinel -G sentinel

# Lock down the environment
USER sentinel
WORKDIR /repo
