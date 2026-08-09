#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCUSAURUS_DIR="${ROOT_DIR}/tools/docusaurus"

echo "Installing docs dependencies..."
cd "${DOCUSAURUS_DIR}"
npm install

echo "Building docs..."
npm run build

echo "Documentation generated at:"
echo "${DOCUSAURUS_DIR}/build"
