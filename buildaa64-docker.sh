# Build Docker image
docker build -f Dockerfile.aa64 -t shim-repro . 2>&1 | tee logs/buildaa64.log

# Run the container and extract the built binary
docker create --name shim-container shim-repro
docker cp shim-container:/out/shimaa64.efi data/shimaa64.efi
sha256sum data/shimaa64.efi > hashes/shimaa64.sha256
docker cp shim-container:/out/toolchain-hashes.txt hashes/toolchain-hashes_aa64.txt
docker cp shim-container:/out/toolchain-info.txt hashes/toolchain-info_aa64.txt
#docker cp shim-container:/out/disassemblyaa64.diff diffs/disassemblyaa64.diff
docker cp shim-container:/out/shimaa64-stripped.efi data/shimaa64-stripped.efi
#docker cp shim-container:/out/ref.dis diffs/refaa64.dis
#docker cp shim-container:/out/built.dis diffs/builtaa64.dis
docker rm shim-container
