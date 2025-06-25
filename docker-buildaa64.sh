# Build Docker image
docker build -f Dockerfile.aa64 -t shim-repro . 2>&1 | tee logs/buildaa64.log

# Run the container and extract the built binary
docker create --name shim-container shim-repro
docker cp shim-container:/out/shimaa64.efi data/shimaa64.efi
docker cp shim-container:/out/toolchain-hashes.txt hashes/toolchain-hashes_aa64.txt
docker cp shim-container:/out/toolchain-info.txt hashes/toolchain-info_aa64.txt
docker rm shim-container
