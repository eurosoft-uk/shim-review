# Build Docker image
docker build -f Dockerfile.x86_64 -t shim-repro . 2>&1 | tee logs/buildx64.log

# Run the container and extract the built binary
docker create --name shim-container shim-repro
docker cp shim-container:/out/shimx64.efi data/shimx64.efi
docker rm shim-container
