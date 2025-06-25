# Build Docker image
docker build -f Dockerfile.x64 -t shim-repro . 2>&1 | tee logs/buildx64.log

# Run the container and extract the built binary
docker create --name shim-container shim-repro
docker cp shim-container:/out/shimx64.efi data/shimx64.efi
docker cp shim-container:/out/toolchain-hashes.txt hashes/toolchain-hashes_x64.txt
docker cp shim-container:/out/toolchain-info.txt hashes/toolchain-info_x64.txt
docker rm shim-container
