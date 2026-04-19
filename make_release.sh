#!/bin/bash
# Creates a release zip archive for the Clutch Python backend.
# iOS distribution: build in Xcode and archive via Product → Archive.
set -e

VERSION="${1:-v1.0.0}"
ARCHIVE_NAME="clutch-${VERSION}"
ARCHIVE_DIR="/tmp/${ARCHIVE_NAME}"

echo "Building Clutch ${VERSION} release archive..."

rm -rf "${ARCHIVE_DIR}"
mkdir -p "${ARCHIVE_DIR}"

cp -r scripts/                              "${ARCHIVE_DIR}/scripts/"
cp cellular_remote_config.json             "${ARCHIVE_DIR}/"
cp enhanced_cellular_security_config.json  "${ARCHIVE_DIR}/"
cp requirements.txt                        "${ARCHIVE_DIR}/"
cp quick_start.sh                          "${ARCHIVE_DIR}/"
cp Dockerfile                              "${ARCHIVE_DIR}/"
cp README.md                               "${ARCHIVE_DIR}/"
cp BUILD.md                                "${ARCHIVE_DIR}/"
[ -f LICENSE ] && cp LICENSE               "${ARCHIVE_DIR}/"

chmod +x "${ARCHIVE_DIR}/quick_start.sh"

cd /tmp
zip -r "${ARCHIVE_NAME}.zip" "${ARCHIVE_NAME}/" --quiet
mv "${ARCHIVE_NAME}.zip" "${OLDPWD}/"
rm -rf "${ARCHIVE_DIR}"
cd "${OLDPWD}"

echo "Created ${ARCHIVE_NAME}.zip"
echo ""
echo "To publish a GitHub release:"
echo "  git tag ${VERSION} && git push origin ${VERSION}"
echo "  gh release create ${VERSION} ${ARCHIVE_NAME}.zip \\"
echo "    --title 'Clutch ${VERSION}' \\"
echo "    --repo ghostintheprompt/clutch"
