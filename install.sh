#!/bin/sh
# process-mcp installer - https://github.com/joemckenney/process-mcp
# Usage: curl -sSf https://raw.githubusercontent.com/joemckenney/process-mcp/main/install.sh | sh

set -e

REPO="joemckenney/process-mcp"
INSTALL_DIR="${PROCESS_MCP_INSTALL_DIR:-$HOME/.local/bin}"

# Colors (if terminal supports it)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    NC=''
fi

info() { printf "${GREEN}info${NC}: %s\n" "$1"; }
warn() { printf "${YELLOW}warn${NC}: %s\n" "$1"; }
error() { printf "${RED}error${NC}: %s\n" "$1" >&2; exit 1; }

detect_os() {
    case "$(uname -s)" in
        Linux*) echo "linux" ;;
        *)      error "process-mcp only runs on Linux. /proc formats are Linux-specific with no equivalent on $(uname -s)." ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  echo "x86_64" ;;
        aarch64|arm64) echo "aarch64" ;;
        *)             error "Unsupported architecture: $(uname -m). Pre-built binaries are available for x86_64 and aarch64 only." ;;
    esac
}

get_target() {
    arch="$1"
    case "$arch" in
        x86_64)  echo "x86_64-unknown-linux-gnu" ;;
        aarch64) echo "aarch64-unknown-linux-gnu" ;;
        *)       error "Unsupported architecture: $arch" ;;
    esac
}

get_latest_version() {
    if command -v curl >/dev/null 2>&1; then
        curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/'
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/'
    else
        error "Neither curl nor wget found. Install one of them."
    fi
}

download() {
    url="$1"
    output="$2"

    if command -v curl >/dev/null 2>&1; then
        curl -sSfL "$url" -o "$output"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$url" -O "$output"
    fi
}

main() {
    os=$(detect_os)
    arch=$(detect_arch)
    target=$(get_target "$arch")

    info "Detected platform: ${os}-${arch} (${target})"

    info "Fetching latest release..."
    version=$(get_latest_version)

    if [ -z "$version" ]; then
        error "Failed to determine latest version. Check https://github.com/${REPO}/releases"
    fi

    info "Latest version: ${version}"

    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"' EXIT

    archive_name="process-mcp-${version}-${target}.tar.gz"
    download_url="https://github.com/${REPO}/releases/download/${version}/${archive_name}"

    info "Downloading ${archive_name}..."
    download "$download_url" "${tmp_dir}/${archive_name}" || error "Failed to download from ${download_url}"

    info "Extracting..."
    tar -xzf "${tmp_dir}/${archive_name}" -C "$tmp_dir"

    extract_dir="${tmp_dir}/process-mcp-${version}-${target}"

    if [ ! -f "${extract_dir}/process-mcp" ]; then
        error "process-mcp binary not found in archive at ${extract_dir}"
    fi

    mkdir -p "$INSTALL_DIR"
    mv "${extract_dir}/process-mcp" "${INSTALL_DIR}/process-mcp"
    chmod +x "${INSTALL_DIR}/process-mcp"
    info "Installed process-mcp to ${INSTALL_DIR}/process-mcp"

    case ":$PATH:" in
        *":${INSTALL_DIR}:"*) ;;
        *)
            warn "${INSTALL_DIR} is not in your PATH"
            echo ""
            echo "Add this to your shell profile:"
            echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
            echo ""
            ;;
    esac

    info "Installation complete. Add the MCP server with:"
    echo "  claude mcp add --transport stdio --scope user process -- process-mcp"
}

main "$@"
