#!/usr/bin/env bash
# setup.sh — Build image, set Docker MCP secrets (if missing), and validate Wazuh endpoints
# Single-file, idempotent-ish script for quick setup and validation
# Usage: chmod +x setup.sh && ./setup.sh
set -euo pipefail

# Load .env if present (safe export)
if [ -f .env ]; then
  echo "Loading .env..."
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

# Defaults (will be overridden by envs if provided)
WAZUH_API_USER=${WAZUH_API_USER:-wazuh}
WAZUH_API_PASS=${WAZUH_API_PASS:-api-pass}
WAZUH_API_URLS=${WAZUH_API_URLS:-https://192.168.x.x:55000,https://127.0.0.1:55000}
INDEXER_USER=${INDEXER_USER:-admin}
INDEXER_PASS=${INDEXER_PASS:-indexer-pass}
INDEXER_URLS=${INDEXER_URLS:-https://192.168.x.x:9200,https://127.0.0.1:9200}
IMAGE_NAME=${IMAGE_NAME:-wazuh_mcp-server}

echo "=== Wazuh MCP Server setup script ==="
echo "Image: $IMAGE_NAME"
echo "Wazuh API URLs: $WAZUH_API_URLS"
echo "Indexer URLs: $INDEXER_URLS"
echo

# 1) Build the Docker image
echo "1) Building Docker image..."
docker build -t "${IMAGE_NAME}" .

# 2) Ensure Docker MCP secrets are set (create if missing)
echo "2) Ensuring Docker MCP secrets..."
ensure_secret() {
  local name="$1"
  local value="$2"
  if docker mcp secret list 2>/dev/null | grep -qw "$name"; then
    echo " - Secret $name already exists, skipping creation."
  else
    echo " - Creating secret $name"
    # docker mcp secret set supports direct assignment
    docker mcp secret set "$name"="$value"
  fi
}

ensure_secret "WAZUH_API_USER" "${WAZUH_API_USER}"
ensure_secret "WAZUH_API_PASS" "${WAZUH_API_PASS}"
ensure_secret "INDEXER_USER" "${INDEXER_USER}"
ensure_secret "INDEXER_PASS" "${INDEXER_PASS}"
ensure_secret "WAZUH_API_URLS" "${WAZUH_API_URLS}"
ensure_secret "INDEXER_URLS" "${INDEXER_URLS}"

echo
echo "Secrets currently in Docker MCP:"
docker mcp secret list || true
echo

# 3) Validate Wazuh API auth (authenticate JWT)
echo "3) Validating Wazuh API authentication (first reachable URL)..."
IFS=',' read -r -a WAZUH_URL_ARRAY <<< "$WAZUH_API_URLS"
WAZUH_FIRST=${WAZUH_URL_ARRAY[0]}
WAZUH_FIRST=${WAZUH_FIRST//[[:space:]]/}
if [ -z "$WAZUH_FIRST" ]; then
  echo "❌ No WAZUH API URL configured. Aborting."
  exit 1
fi

echo " - Testing auth against: $WAZUH_FIRST"
AUTH_RESP=$(curl -k -s -u "${WAZUH_API_USER}:${WAZUH_API_PASS}" -X POST "${WAZUH_FIRST%/}/security/user/authenticate?raw=true" || true)
if [ -z "$AUTH_RESP" ]; then
  echo "❌ Authentication failed or no response from Wazuh API at $WAZUH_FIRST"
  echo "  Try: curl -k -u \"$WAZUH_API_USER:...\" -X POST \"$WAZUH_FIRST/security/user/authenticate?raw=true\""
else
  echo "✅ Authentication endpoint returned a token (length ${#AUTH_RESP})."
fi
echo

# 4) Validate indexer health (first reachable)
echo "4) Validating Indexer health (first reachable URL)..."
IFS=',' read -r -a INDEXER_URL_ARRAY <<< "$INDEXER_URLS"
INDEXER_FIRST=${INDEXER_URL_ARRAY[0]}
INDEXER_FIRST=${INDEXER_FIRST//[[:space:]]/}
if [ -z "$INDEXER_FIRST" ]; then
  echo "❌ No INDEXER URL configured. Aborting."
  exit 1
fi

echo " - Testing indexer health against: $INDEXER_FIRST"
HTTP_CODE=$(curl -k -s -o /dev/null -u "${INDEXER_USER}:${INDEXER_PASS}" -w '%{http_code}' "${INDEXER_FIRST%/}/_cluster/health" || true)
if [ "$HTTP_CODE" = "200" ]; then
  echo "✅ Indexer reachable and returned HTTP 200."
else
  echo "❌ Indexer unreachable or returned HTTP ${HTTP_CODE}."
  echo "  Try: curl -k -u \"${INDEXER_USER}:...\" \"${INDEXER_FIRST%/}/_cluster/health\""
fi
echo

# 5) Print next steps
echo "=== Done ==="
echo "Next steps:"
echo " - Ensure your custom.yaml is present at ~/.docker/mcp/catalogs/custom.yaml and points to image ${IMAGE_NAME}:latest"
echo " - Start/Restart the MCP Gateway used by Claude Desktop so it picks up the catalog"
echo " - In Claude Desktop, your tools should appear: get_running_agents, wazuh_FIM_Alerts, etc."
echo
echo "If you need a remote push to Docker Hub, tag and push:"
echo "  docker tag ${IMAGE_NAME}:latest youruser/${IMAGE_NAME}:latest"
echo "  docker push youruser/${IMAGE_NAME}:latest"
