#!/bin/bash

export CERTIFIER_PROTOTYPE=/root/certifier-framework-for-confidential-computing
export EXAMPLE_DIR=$CERTIFIER_PROTOTYPE/sample_apps/simple_app

cd $EXAMPLE_DIR


# Cold init
$EXAMPLE_DIR/example_app.exe \
  --data_dir=./app2_data/ \
  --operation=cold-init \
  --measurement_file="example_app.measurement" \
  --policy_store_file=policy_store \
  --print_all=true

# Get certified
$EXAMPLE_DIR/example_app.exe \
  --data_dir=./app2_data/ \
  --operation=get-certified \
  --measurement_file="example_app.measurement" \
  --policy_store_file=policy_store \
  --print_all=true

# Run as server
$EXAMPLE_DIR/example_app.exe \
  --data_dir=./app2_data/ \
  --operation=run-app-as-server \
  --policy_store_file=policy_store \
  --print_all=true \
#   --server_app_host=0.0.0.0 \
#   --server_app_port=8124 \
#   --policy_host=0.0.0.0 \
#   --policy_port=8123
