#!/bin/bash

export CERTIFIER_PROTOTYPE=/root/certifier-framework-for-confidential-computing
export EXAMPLE_DIR=$CERTIFIER_PROTOTYPE/sample_apps/simple_app

cd $EXAMPLE_DIR

# Cold init
$EXAMPLE_DIR/example_app.exe \
  --data_dir=./app1_data/ \
  --operation=cold-init \
  --measurement_file="example_app.measurement" \
  --policy_store_file=policy_store \
  --print_all=true

# Get certified
$EXAMPLE_DIR/example_app.exe \
  --data_dir=./app1_data/ \
  --operation=get-certified \
  --measurement_file="example_app.measurement" \
  --policy_store_file=policy_store \
  --print_all=true

# Run as client
$EXAMPLE_DIR/example_app.exe \
  --data_dir=./app1_data/ \
  --operation=run-app-as-client \
  --policy_store_file=policy_store \
  --print_all=true \
  --repository_url="https://github.com/galaxyproject/galaxy-test-data.git" \
  --analysis_type="sequence_quality" \
  --dataset_name="2.fastq" \
  --parameters="--quiet --threads 2"

# gatk --java-options "-Xmx4G" HaplotypeCaller -R GCF_000005845.2_ASM584v2_genomic.fna  -I sample.bam -O /tmp/bio_fasta/results/sample_indels.vcf --emit-ref-confidence GVCF --dont-use-soft-clipped-bases --standard-min-confidence-threshold-for-calling 20

