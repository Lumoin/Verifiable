# Builds the TCG ms-tpm-20-ref software TPM simulator (tpm2-simulator) for the
# RequiresTpmSimulator acceptance lane. It speaks the Microsoft simulator TCP
# protocol: command port 2321 (TPM_REMOTE_HANDSHAKE / TPM_SEND_COMMAND) and
# platform port 2322 (power/NV/reset signals).
#
# Build context MUST be a checkout of ms-tpm-20-ref (the directory containing the
# TPMCmd folder), e.g. tempdocs/tpm/external/ms-tpm-20-ref:
#
#   docker build -f test/Verifiable.Tests/TestInfrastructure/TpmSimulator/Dockerfile \
#     -t verifiable-tpm-simulator /path/to/ms-tpm-20-ref
#   docker run -d --rm --name verifiable-tpm-simulator -p 2321:2321 -p 2322:2322 \
#     verifiable-tpm-simulator
#
# The simulator binds INADDR_ANY, so the published ports are reachable on the host. Its bring-up lines
# ("Manufacturing NV state...", "TPM command server listening on port 2321", "Platform server listening on
# port 2322") go to stdout; view them with `docker logs verifiable-tpm-simulator`, or run without -d for a
# foreground first-time bring-up.
FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y autoconf-archive pkg-config build-essential automake gcc libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY TPMCmd ./TPMCmd

# The source may be checked out on Windows with CRLF line endings, which breaks the bootstrap shebang
# (/usr/bin/env: 'sh\r') and the autotools inputs. Normalize the build scripts to LF before building.
RUN cd TPMCmd \
    && find . -type f \( -name bootstrap -o -name 'configure.ac' -o -name 'Makefile.am' -o -name '*.m4' -o -name '*.sh' \) -print0 | xargs -0 sed -i 's/\r$//' \
    && ./bootstrap \
    && ./configure \
    && make

EXPOSE 2321 2322

# -m manufactures fresh NV state on start; combined with a --rm container this gives a clean TPM each run.
ENTRYPOINT ["/build/TPMCmd/Simulator/src/tpm2-simulator"]
CMD ["-m"]
