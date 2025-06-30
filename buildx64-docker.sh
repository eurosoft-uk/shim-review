# Build Docker image
docker build --no-cache -f Dockerfile.x64 -t shim-repro . 2>&1 | tee logs/buildx64.log

# Run the container and extract the built binary
docker create --name shim-container shim-repro
docker cp shim-container:/out/shimx64.efi data/shimx64.efi
sha256sum data/shimx64.efi > hashes/shimx64.sha256
docker cp shim-container:/out/toolchain-hashes.txt hashes/toolchain-hashes_x64.txt
docker cp shim-container:/out/toolchain-info.txt hashes/toolchain-info_x64.txt
#docker cp shim-container:/out/disassemblyx64.diff diffs/disassemblyx64.diff
docker cp shim-container:/out/shimx64-stripped.efi data/shimx64-stripped.efi
#docker cp shim-container:/out/ref.dis diffs/refx64.dis
#docker cp shim-container:/out/built.dis diffs/builtx64.dis
docker rm shim-container
