# HSP dev/test container — ALL npm/node execution happens in here, never on the
# host (user directive 2026-06-10: protect the host Mac from dependency risk).
#
#   docker build -f docker/dev.Dockerfile -t hsp-dev .
#   # install deps into the persistent volume (re-run after lockfile changes):
#   docker run --rm -v "$PWD":/work -v hsp-node-modules:/work/node_modules hsp-dev \
#     bash -lc "npm ci && npm rebuild better-sqlite3 --ignore-scripts=false --foreground-scripts"
#   # gates:
#   docker run --rm -v "$PWD":/work -v hsp-node-modules:/work/node_modules hsp-dev \
#     bash -lc "npm run check"
#
# Images: node = Docker Official Image; anvil binary copied from the official
# foundry-rs image (no foundryup curl|bash). The named volume keeps the
# linux-native node_modules out of the host checkout.
FROM ghcr.io/foundry-rs/foundry:stable AS foundry

FROM node:24-bookworm
COPY --from=foundry /usr/local/bin/anvil /usr/local/bin/anvil
COPY --from=foundry /usr/local/bin/forge /usr/local/bin/forge
WORKDIR /work
CMD ["bash"]
