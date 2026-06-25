#!/usr/bin/env bash
# =============================================================================
# Azure Resource Guardian — Docker Hub build & push
# =============================================================================
#
# Builds and pushes backend, worker, and frontend images to Docker Hub.
# Default: linux/amd64 only (fast — ~5 min).
# Optional: add --arm to also build linux/arm64 (slow — ~60 min, uses QEMU).
#
# Prerequisites:
#   1. docker login
#   2. docker buildx create --use --name arg-builder --driver docker-container --bootstrap
#      (one-time setup — only needed for --arm builds)
#
# Usage:
#   ./build-push.sh              # amd64 only, push to Docker Hub
#   ./build-push.sh --arm        # amd64 + arm64 (multi-arch), push
#   ./build-push.sh --no-push    # amd64 only, build locally (no push)
#   ./build-push.sh --arm --no-push  # multi-arch, local only
#
# Images pushed:
#   jahmed22/azure-resource-guardian-backend:0.1   + :latest
#   jahmed22/azure-resource-guardian-worker:0.1    + :latest
#   jahmed22/azure-resource-guardian-frontend:0.1  + :latest
#
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
REGISTRY="jahmed22"
APP_NAME="azure-resource-guardian"
VERSION="0.1"
BUILDER_NAME="arg-builder"

# ---------------------------------------------------------------------------
# Parse flags
# ---------------------------------------------------------------------------
PUSH=true
MULTI_ARCH=false

for arg in "$@"; do
  case "$arg" in
    --no-push)  PUSH=false ;;
    --arm)      MULTI_ARCH=true ;;
    --help|-h)
      sed -n '3,20p' "$0" | sed 's/^# \?//'
      exit 0 ;;
  esac
done

if [[ "${MULTI_ARCH}" == true ]]; then
  PLATFORMS="linux/amd64,linux/arm64"
else
  PLATFORMS="linux/amd64"
fi

# ---------------------------------------------------------------------------
# Colours
# ---------------------------------------------------------------------------
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; RESET='\033[0m'

log()  { echo -e "${CYAN}▶ $*${RESET}"; }
ok()   { echo -e "${GREEN}✓ $*${RESET}"; }
warn() { echo -e "${YELLOW}⚠ $*${RESET}"; }

# ---------------------------------------------------------------------------
# Ensure we're in the project root
# ---------------------------------------------------------------------------
cd "$(dirname "$0")"

log "Azure Resource Guardian — Docker Hub build"
echo "  Registry  : ${REGISTRY}"
echo "  Version   : ${VERSION}"
echo "  Platforms : ${PLATFORMS}"
echo "  Push      : ${PUSH}"
echo ""

# ---------------------------------------------------------------------------
# For multi-arch (--arm) we need a BuildKit container builder.
# For amd64-only the default docker driver is sufficient and faster.
# ---------------------------------------------------------------------------
if [[ "${MULTI_ARCH}" == true ]]; then
  if ! docker buildx inspect "${BUILDER_NAME}" &>/dev/null; then
    log "Creating multi-arch BuildKit builder '${BUILDER_NAME}'..."
    docker buildx create \
      --name "${BUILDER_NAME}" \
      --driver docker-container \
      --driver-opt network=host \
      --bootstrap
    ok "Builder created"
  fi
  docker buildx use "${BUILDER_NAME}"
  log "Multi-arch build enabled (amd64 + arm64) — expect ~60 min"
else
  log "Building amd64 only — use --arm flag to also build arm64"
fi

# ---------------------------------------------------------------------------
# Helper — build and optionally push a single image
# ---------------------------------------------------------------------------
build_image() {
  local service="$1"
  local dockerfile="$2"
  local extra_args="${3:-}"
  local repo="${REGISTRY}/${APP_NAME}-${service}"

  log "Building ${service} → ${repo}:${VERSION} + :latest"

  if [[ "${MULTI_ARCH}" == true ]]; then
    # Multi-arch requires buildx + --push (cannot load multi-arch locally)
    local push_flag="--push"
    if [[ "${PUSH}" == false ]]; then
      warn "  --arm + --no-push: will build but not push (images won't be loadable locally)"
    fi
    # shellcheck disable=SC2086
    docker buildx build \
      --platform "${PLATFORMS}" \
      -t "${repo}:${VERSION}" \
      -t "${repo}:latest" \
      --file "${dockerfile}" \
      --progress=plain \
      ${push_flag} \
      ${extra_args} \
      .
  else
    # amd64-only: plain docker build is faster and loads into local daemon
    docker build \
      -t "${repo}:${VERSION}" \
      -t "${repo}:latest" \
      --file "${dockerfile}" \
      ${extra_args} \
      .
    if [[ "${PUSH}" == true ]]; then
      docker push "${repo}:${VERSION}"
      docker push "${repo}:latest"
    fi
  fi

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
