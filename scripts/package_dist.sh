#!/usr/bin/env bash
# ==============================================================================
# Exactor WAF Guardian - Linux Distribution Packager
# Generates a standalone, zero-dependency tar.gz bundle for client distribution.
# ==============================================================================

set -euo pipefail

VERSION="v0.1.0"
NO_REBUILD=false

for arg in "$@"; do
    if [[ "$arg" == "--no-rebuild" ]]; then
        NO_REBUILD=true
    fi
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${PROJECT_ROOT}/dist"
ARCH="$(uname -m)"

case "${ARCH}" in
    x86_64|amd64) TARGET_NAME="linux-x86_64" ;;
    aarch64|arm64) TARGET_NAME="linux-aarch64" ;;
    *) TARGET_NAME="linux-${ARCH}" ;;
esac

STAGING_DIR="${DIST_DIR}/exactor-waf-guardian-${VERSION}-${TARGET_NAME}"
TAR_FILE="${DIST_DIR}/exactor-waf-guardian-${VERSION}-${TARGET_NAME}.tar.gz"

echo "============================================================"
echo "📦 Packaging Exactor WAF Guardian for Linux (${TARGET_NAME})"
echo "============================================================"

# 1. Build or Locate Release Binary
RELEASE_BIN=""
if [[ -f "${PROJECT_ROOT}/target/release/exactor-waf-guardian" ]]; then
    RELEASE_BIN="${PROJECT_ROOT}/target/release/exactor-waf-guardian"
elif [[ -f "${PROJECT_ROOT}/../target/release/exactor-waf-guardian" ]]; then
    RELEASE_BIN="${PROJECT_ROOT}/../target/release/exactor-waf-guardian"
fi

if [[ -z "${RELEASE_BIN}" ]] || [[ "$NO_REBUILD" == "false" ]]; then
    echo "Building release binary..."
    (cd "${PROJECT_ROOT}" && cargo build --release -p exactor-waf-guardian)
    if [[ -f "${PROJECT_ROOT}/target/release/exactor-waf-guardian" ]]; then
        RELEASE_BIN="${PROJECT_ROOT}/target/release/exactor-waf-guardian"
    elif [[ -f "${PROJECT_ROOT}/../target/release/exactor-waf-guardian" ]]; then
        RELEASE_BIN="${PROJECT_ROOT}/../target/release/exactor-waf-guardian"
    fi
fi

if [[ -z "${RELEASE_BIN}" ]] || [[ ! -f "${RELEASE_BIN}" ]]; then
    echo "Error: Release binary not found in target directories."
    exit 1
fi

# 2. Prepare Dist & Staging Directory
rm -rf "${STAGING_DIR}"
mkdir -p "${STAGING_DIR}/bin"

# 3. Copy Assets
cp "${RELEASE_BIN}" "${STAGING_DIR}/exactor-waf-guardian"
cp "${RELEASE_BIN}" "${STAGING_DIR}/bin/exactor-waf-guardian"
chmod +x "${STAGING_DIR}/exactor-waf-guardian"
chmod +x "${STAGING_DIR}/bin/exactor-waf-guardian"
cp "${PROJECT_ROOT}/waf_config.toml" "${STAGING_DIR}/waf_config.toml"
cp "${PROJECT_ROOT}/install.sh" "${STAGING_DIR}/install.sh"
chmod +x "${STAGING_DIR}/install.sh"
cp "${PROJECT_ROOT}/uninstall.sh" "${STAGING_DIR}/uninstall.sh"
chmod +x "${STAGING_DIR}/uninstall.sh"
cp "${PROJECT_ROOT}/exactor-waf.service" "${STAGING_DIR}/exactor-waf.service"

# 4. Generate README_INSTALL.txt
cat << EOF > "${STAGING_DIR}/README_INSTALL.txt"
================================================================================
  EXACTOR WAF GUARDIAN - ZERO-DEPENDENCY CLIENT INSTALLATION PACKAGE
  Deterministic SAT Cyber-Defense & Sub-millisecond Reverse Proxy
  Powered by EXACTOR Core & https://exactor.tech
================================================================================

Este paquete es 100% autocontenido. El cliente NO necesita tener instalado Rust,
Cargo, Python, GCC, Make ni ninguna otra dependencia en su servidor Linux.

OPCION A: INSTALACION AUTOMATICA CON SYSTEMD (RECOMENDADA)
--------------------------------------------------------------------------------
1. Extraiga el archivo comprimido y entre a la carpeta:
     tar -xzf exactor-waf-guardian-${VERSION}-${TARGET_NAME}.tar.gz
     cd exactor-waf-guardian-${VERSION}-${TARGET_NAME}
2. Ejecute el instalador como root:
     sudo ./install.sh

   El instalador hara automaticamente:
   - Instalar el binario precompilado en /usr/local/bin/exactor-waf-guardian
   - Crear la configuracion en /etc/exactor/waf_config.toml
   - Registrar e iniciar el servicio systemd "exactor-waf.service"

OPCION B: EJECUCION PORTABLE (SIN INSTALAR)
--------------------------------------------------------------------------------
Si solo desea probar el firewall sin tocar rutas del sistema:
1. Ejecute directamente el binario:
     ./exactor-waf-guardian proxy --config ./waf_config.toml
2. Probar inspeccion formal de un payload:
     ./exactor-waf-guardian inspect --query "id=1' OR 1=1--"

DESINSTALACION LIMPIA:
--------------------------------------------------------------------------------
Para remover completamente el servicio y binario:
   sudo ./uninstall.sh
================================================================================
EOF

# 5. Compress into tar.gz
rm -f "${TAR_FILE}"
(cd "${DIST_DIR}" && tar -czf "${TAR_FILE}" "$(basename "${STAGING_DIR}")")

# 6. Checksum
SHA=$(sha256sum "${TAR_FILE}" | awk '{print $1}')
echo ""
echo "============================================================"
echo "✅ Linux Client Distribution Package ready!"
echo "   Archive  : ${TAR_FILE}"
echo "   SHA256   : ${SHA}"
echo "============================================================"
