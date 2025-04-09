# Access Log Analyzer

Tiny tool for converting access logs into JSON for filtering/processing.

## Usage

Sync S3 directory with access logs into ./assets

```sh
./s3-sync.sh s3://bucket-name/path/to/logs/of/interest
```

Parse logs in ./assets

```sh
cargo run
```

Filter with JQ

```sh
cargo run | jq -r '.[] | select(.target_processing_time == null)'
```