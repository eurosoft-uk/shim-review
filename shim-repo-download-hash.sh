ARG SHIM_VERSION=16.0
ARG SHIM_TARBALL_URL=https://github.com/rhboot/shim/releases/download/${SHIM_VERSION}/shim-${SHIM_VERSION}.tar.bz2
ARG SHIM_TARBALL=shim-${SHIM_VERSION}.tar.bz2
ARG SHIM_SHA256=d503f778dc75895d3130da07e2ff23d2393862f95b6cd3d24b10cbd4af847217
   
# Download official shim release
RUN wget -q ${SHIM_TARBALL_URL}

# Verify checksum (fail if not matching)
RUN echo "${SHIM_SHA256}  ${SHIM_TARBALL}" | sha256sum -c -