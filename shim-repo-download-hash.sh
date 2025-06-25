# Clone and export as tar.gz
git clone https://github.com/rhboot/shim.git 
cd shim
git checkout b86b909f1e8281e0f30c3b5b5f697de185135f98
git archive --format=tar.gz --output=shim-source.tar.gz HEAD
sha256sum shim-source.tar.gz > ../shim-source.sha256
cp shim-source.tar.gz ..
cd ..
rm -rf shim