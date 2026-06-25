#!/usr/bin/env bash
# =============================================================================
# Azure Resource Guardian — Multi-arch Docker Hub build & push
# =============================================================================
#
# Builds linux/amd64 + linux/arm64 images for backend, worker, and frontend,
# tags them as both 0.1 and latest, and pushes to Docker Hub.
#
# Prerequisites:
#   1. docker login                          # authenticate to Docker Hub
#   2. docker buildx ls                      # confirm a multi-arch builder exists
#   3. docker buildx create --use --name arg-builder --driver docker-container
#      (only needed once — creates a BuildKit builder that supports multi-arch)
#
# Usage:
#   chmod +x build-push.sh
#   ./build-push.sh            # build + push all three images
#   ./build-push.sh --no-push  # build locally only (for testing)
#
# Images pushed:
#   jahmed22/azure-resource-guardian-backend:0.1
#   jahmed22/azure-resource-guardian-backend:latest
#   jahmed22/azure-resource-guardian-worker:0.1
#   jahmed22/azure-resource-guardian-worker:latest
#   jahmed22/azure-resource-guardian-frontend:0.1
#   jahmed22/azure-resource-guardian-frontend:latest
#
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration — edit these if the version or Hub namespace ever change
# ---------------------------------------------------------------------------
REGISTRY="jahmed22"
APP_NAME="azure-resource-guardian"   # Docker Hub repo prefix
VERSION="0.1"
PLATFORMS="linux/amd64,linux/arm64"
BUILDER_NAME="arg-builder"

# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------
PUSH=true
if [[ "${1:-}" == "--no-push" ]]; then
  PUSH=false
  echo "ℹ️  --no-push: images will be built but not pushed to Docker Hub"
fi

# ---------------------------------------------------------------------------
# Colours
# ---------------------------------------------------------------------------
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; RESET='\033[0m'

log()  { echo -e "${CYAN}▶ $*${RESET}"; }
ok()   { echo -e "${GREEN}✓ $*${RESET}"; }
warn() { echo -e "${YELLOW}⚠ $*${RESET}"; }

# ---------------------------------------------------------------------------
# Ensure we're in the project root (the directory containing this script)
# ---------------------------------------------------------------------------
cd "$(dirname "$0")"

log "Azure Resource Guardian — Docker Hub multi-arch build"
echo "  Registry  : ${REGISTRY}"
echo "  Version   : ${VERSION}"
echo "  Platforms : ${PLATFORMS}"
echo "  Push      : ${PUSH}"
echo ""

# ---------------------------------------------------------------------------
# Ensure a multi-arch BuildKit builder is active
# ---------------------------------------------------------------------------
if ! docker buildx inspect "${BUILDER_NAME}" &>/dev/null; then
  log "Creating BuildKit multi-arch builder '${BUILDER_NAME}'..."
  docker buildx create \
    --name "${BUILDER_NAME}" \
    --driver docker-container \
    --driver-opt network=host \
    --bootstrap
  ok "Builder created"
else
  log "Using existing builder '${BUILDER_NAME}'"
fi

docker buildx use "${BUILDER_NAME}"

# ---------------------------------------------------------------------------
# Helper — build (and optionally push) a single image
# ---------------------------------------------------------------------------
build_image() {
  local service="$1"       # backend | worker | frontend
  local dockerfile="$2"    # docker/Dockerfile.backend etc.
  local repo="${REGISTRY}/${APP_NAME}-${service}"
  local tags="-t ${repo}:${VERSION} -t ${repo}:latest"
  local extra_args="${3:-}"

  log "Building ${service} → ${repo}:${VERSION} + :latest"

  local push_flag=""
  if [[ "${PUSH}" == true ]]; then
    push_flag="--push"
  else
    # Without --push, buildx loads into local docker daemon (amd64 only)
    push_flag="--load"
    # Multi-arch --load isn't supported; fall back to current arch for local test
    PLATFORMS_OVERRIDE="linux/$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"
    warn "  Local load — building ${PLATFORMS_OVERRIDE} only (multi-arch requires --push)"
    extra_args="${extra_args} --platform ${PLATFORMS_OVERRIDE}"
  fi

  # shellcheck disable=SC2086
  docker buildx build \
    --platform "${PLATFORMS}" \
    ${tags} \
    --file "${dockerfile}" \
    ${push_flag} \
    ${extra_args} \
    .

  ok "${service} done"
}

# ---------------------------------------------------------------------------
# Build each service
# ---------------------------------------------------------------------------
START=$(date +%s)

build_image "backend"  "docker/Dockerfile.backend"
build_image "worker"   "docker/Dockerfile.worker"
build_image "frontend" "docker/Dockerfile.frontend" "--build-arg VITE_API_URL=/api/v1"

END=$(date +%s)
ELAPSED=$(( END - START ))

echo ""
ok "All images built in ${ELAPSED}s"

if [[ "${PUSH}" == true ]]; then
  echo ""
  echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo -e "${GREEN}  Pushed to Docker Hub:${RESET}"
  echo "    ${REGISTRY}/${APP_NAME}-backend:${VERSION}"
  echo "    ${REGISTRY}/${APP_NAME}-backend:latest"
  echo "    ${REGISTRY}/${APP_NAME}-worker:${VERSION}"
  echo "    ${REGISTRY}/${APP_NAME}-worker:latest"
  echo "    ${REGISTRY}/${APP_NAME}-frontend:${VERSION}"
  echo "    ${REGISTRY}/${APP_NAME}-frontend:latest"
  echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
fi
