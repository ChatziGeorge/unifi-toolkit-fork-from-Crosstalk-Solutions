#!/bin/bash
#
# UI Toolkit - Setup Wizard
# Interactive configuration for local or production deployment
#

set -e

# Colors for output (using $'...' to properly interpret escape sequences)
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
CYAN=$'\033[0;36m'
NC=$'\033[0m' # No Color
BOLD=$'\033[1m'

# Functions
print_banner() {
    echo ""
    printf "${BLUE}=================================================================${NC}\n"
    printf "${BLUE}          ${BOLD}UI Toolkit - Installation Wizard${NC}\n"
    printf "${BLUE}\n"
    printf "        Network Management Tools for UniFi\n"
    printf "${BLUE}=================================================================${NC}\n"
    echo ""
}

print_success() {
    printf "${GREEN}✓${NC} %s\n" "$1"
}

# Messages go to stderr so they stay visible when called inside $(...)
print_error() {
    printf "${RED}✗${NC} %s\n" "$1" >&2
}

print_warning() {
    printf "${YELLOW}⚠${NC} %s\n" "$1" >&2
}

print_info() {
    printf "${CYAN}ℹ${NC} %s\n" "$1" >&2
}

# Python is optional: it is only a helper for key generation / password
# hashing, and both have non-Python fallbacks (openssl, htpasswd).
check_python() {
    PYTHON_CMD=""
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
    elif command -v python &> /dev/null; then
        PYTHON_CMD="python"
    else
        print_warning "Python 3 not found - using openssl/htpasswd instead"
        return 0
    fi

    PYTHON_VERSION=$($PYTHON_CMD -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "unknown")
    print_success "Python $PYTHON_VERSION detected"
}

# Generate Fernet encryption key (urlsafe base64 of 32 random bytes).
# Standard library only - no 'cryptography' package needed.
generate_encryption_key() {
    local key=""
    if [ -n "$PYTHON_CMD" ]; then
        key=$($PYTHON_CMD -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())" 2>/dev/null || true)
    fi
    if [ -z "$key" ] && command -v openssl &> /dev/null; then
        key=$(openssl rand -base64 32 | tr '+/' '-_')
    fi
    if [ ${#key} -ne 44 ]; then
        print_error "Failed to generate encryption key"
        print_info "Install Python 3 or openssl and try again."
        exit 1
    fi
    echo "$key"
}

# Hash password with bcrypt.
# Tries Python bcrypt first, then htpasswd (built into macOS; on Ubuntu:
# sudo apt install apache2-utils). The password is passed on stdin so it
# never appears in the process list.
hash_password() {
    local password="$1"
    local hash=""
    if [ -n "$PYTHON_CMD" ]; then
        hash=$(printf '%s\n' "$password" | $PYTHON_CMD -c "
import sys
import bcrypt
password = sys.stdin.readline().rstrip('\n')
print(bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode())
" 2>/dev/null || true)
    fi
    if [ -z "$hash" ] && command -v htpasswd &> /dev/null; then
        hash=$(printf '%s\n' "$password" | htpasswd -niBC 12 user 2>/dev/null | cut -d: -f2- | tr -d '\r\n' || true)
    fi
    if [[ ! "$hash" =~ ^\$2[aby]\$ ]]; then
        print_error "Failed to hash password"
        print_info "Install either the Python bcrypt package (pip install bcrypt)"
        print_info "or htpasswd (Ubuntu: sudo apt install apache2-utils) and try again."
        exit 1
    fi
    echo "$hash"
}

# Validate a LAN host: an IPv4 address, a single-label name, or a dotted name
# (toolkit.lan, nas.local, server.home.arpa, ...)
validate_lan_host() {
    local host="$1"
    if [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 0
    fi
    if [[ "$host" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        return 0
    fi
    return 1
}

# Ask for admin username + password; sets AUTH_USERNAME and AUTH_PASSWORD_HASH
prompt_credentials() {
    echo "Enter the admin username for UI Toolkit access."
    echo ""
    read -p "Admin username [admin]: " AUTH_USERNAME
    AUTH_USERNAME=${AUTH_USERNAME:-admin}
    print_success "Username: $AUTH_USERNAME"
    echo ""

    echo "Enter the admin password."
    echo "Requirements: 12+ characters, uppercase, lowercase, and numbers"
    echo ""

    while true; do
        read -s -p "Admin password: " password
        echo ""

        if ! validate_password "$password"; then
            echo ""
            continue
        fi

        read -s -p "Confirm password: " password_confirm
        echo ""

        if [ "$password" != "$password_confirm" ]; then
            echo ""
            print_error "Passwords do not match. Please try again."
            echo ""
            continue
        fi

        break
    done

    echo ""
    print_info "Hashing password..."
    AUTH_PASSWORD_HASH=$(hash_password "$password")
    print_success "Password configured"
    echo ""
}

# Validate password meets requirements
validate_password() {
    local password="$1"
    local errors=()

    # Check length
    if [ ${#password} -lt 12 ]; then
        errors+=("Password must be at least 12 characters long")
    fi

    # Check for lowercase
    if ! [[ "$password" =~ [a-z] ]]; then
        errors+=("Password must contain at least one lowercase letter")
    fi

    # Check for uppercase
    if ! [[ "$password" =~ [A-Z] ]]; then
        errors+=("Password must contain at least one uppercase letter")
    fi

    # Check for number
    if ! [[ "$password" =~ [0-9] ]]; then
        errors+=("Password must contain at least one number")
    fi

    if [ ${#errors[@]} -gt 0 ]; then
        echo ""
        print_error "Password does not meet requirements:"
        for error in "${errors[@]}"; do
            echo "  - $error"
        done
        return 1
    fi

    return 0
}

# Validate domain name format
validate_domain() {
    local domain="$1"
    if [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$ ]]; then
        return 0
    fi
    return 1
}

# Check if .env already exists
check_existing_config() {
    if [ -d ".env" ]; then
        echo ""
        print_error "'.env' exists as a directory, not a file. Please remove it and re-run setup:"
        echo "  rm -rf .env"
        exit 1
    fi
    if [ -f ".env" ]; then
        echo ""
        print_warning "An existing .env file was found!"
        echo ""
        read -p "Do you want to overwrite it? [y/N]: " overwrite
        if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
            print_info "Setup cancelled. Your existing configuration was not modified."
            exit 0
        fi
        echo ""
    fi
}

# Main setup flow
main() {
    print_banner

    # Check prerequisites
    printf "${BOLD}Checking prerequisites...${NC}\n"
    echo ""
    check_python
    echo ""

    # Check for existing config
    check_existing_config

    # Step 1: Choose deployment type
    printf "${BOLD}Step 1: Deployment Type${NC}\n"
    echo ""
    echo "How will you be deploying UI Toolkit?"
    echo ""
    printf "  1) ${BOLD}Local${NC} - Running on your LAN only\n"
    echo "     • No authentication required"
    echo "     • No HTTPS (uses HTTP)"
    echo "     • Access via http://localhost:8000"
    echo ""
    printf "  2) ${BOLD}LAN with login${NC} - Running on your LAN, password protected\n"
    echo "     • Authentication required"
    echo "     • HTTPS with a self-signed certificate (no public domain needed)"
    echo "     • Access via https://<server IP or LAN name>"
    echo ""
    printf "  3) ${BOLD}Production${NC} - Internet-facing deployment\n"
    echo "     • Authentication required"
    echo "     • HTTPS with Let's Encrypt"
    echo "     • Requires a domain name"
    echo ""

    # LAN mode runs the app in production (auth) mode behind Caddy with
    # 'tls internal' - the session cookie is HTTPS-only, so plain HTTP
    # cannot hold a login.
    LAN_MODE=false
    while true; do
        read -p "Select deployment type [1-3]: " deployment_choice
        case $deployment_choice in
            1)
                DEPLOYMENT_TYPE="local"
                break
                ;;
            2)
                DEPLOYMENT_TYPE="production"
                LAN_MODE=true
                break
                ;;
            3)
                DEPLOYMENT_TYPE="production"
                break
                ;;
            *)
                print_error "Invalid choice. Please enter 1, 2 or 3."
                ;;
        esac
    done

    echo ""
    if [ "$LAN_MODE" == true ]; then
        print_success "Selected: LAN with login deployment"
    else
        print_success "Selected: $DEPLOYMENT_TYPE deployment"
    fi
    echo ""

    # Step 2: Generate encryption key
    printf "${BOLD}Step 2: Generating Encryption Key${NC}\n"
    echo ""
    print_info "Generating secure encryption key..."
    ENCRYPTION_KEY=$(generate_encryption_key)
    print_success "Encryption key generated"
    echo ""

    # Initialize variables
    DOMAIN=""
    AUTH_USERNAME=""
    AUTH_PASSWORD_HASH=""

    # Step 3: LAN-with-login configuration
    if [ "$LAN_MODE" == true ]; then
        printf "${BOLD}Step 3: LAN Configuration${NC}\n"
        echo ""
        echo "Enter the IP address or LAN hostname you will open in the browser"
        echo "(e.g., 192.168.1.50, toolkit.lan, nas.local)."
        echo "Caddy issues a self-signed certificate for exactly this name."
        echo ""

        while true; do
            read -p "Server IP or LAN hostname: " DOMAIN
            if validate_lan_host "$DOMAIN"; then
                break
            else
                print_error "Invalid IP address or hostname. Please try again."
            fi
        done

        print_success "Host: $DOMAIN"
        echo ""

        prompt_credentials

    # Step 3: Production-specific configuration
    elif [ "$DEPLOYMENT_TYPE" == "production" ]; then
        printf "${BOLD}Step 3: Production Configuration${NC}\n"
        echo ""

        # Security notice
        printf "${YELLOW}=================================================================${NC}\n"
        printf "${YELLOW}  ${BOLD}IMPORTANT: Network Security${NC}\n"
        printf "${YELLOW}=================================================================${NC}\n"
        printf "${YELLOW}  When managing multiple UniFi sites, always use site-to-site\n"
        printf "  VPN connections. Never expose UniFi controllers directly to\n"
        printf "  the internet via port forwarding.\n"
        printf "\n"
        printf "  Recommended: WireGuard, IPSec, Tailscale, or UniFi VPN${NC}\n"
        printf "${YELLOW}=================================================================${NC}\n"
        echo ""

        # Domain name
        echo "Enter your domain name (e.g., toolkit.yourdomain.com)"
        echo "This domain must point to this server's IP address."
        echo ""

        while true; do
            read -p "Domain name: " DOMAIN
            if validate_domain "$DOMAIN"; then
                break
            else
                print_error "Invalid domain format. Please enter a valid domain name."
            fi
        done

        print_success "Domain: $DOMAIN"
        echo ""

        prompt_credentials
    fi

    # Step 4: Write .env file
    if [ "$DEPLOYMENT_TYPE" == "production" ]; then
        STEP_NUM="4"
    else
        STEP_NUM="3"
    fi

    printf "${BOLD}Step $STEP_NUM: Writing Configuration${NC}\n"
    echo ""

    cat > .env << EOF
# ============================================
# UI Toolkit Configuration
# ============================================
# Generated by setup wizard - $(date)
# Deployment type: ${DEPLOYMENT_TYPE}
# ============================================

# ============================================
# DEPLOYMENT SETTINGS
# ============================================

# Deployment type: local or production
DEPLOYMENT_TYPE=$DEPLOYMENT_TYPE
EOF

    # Add production-specific settings
    if [ "$LAN_MODE" == true ]; then
        cat >> .env << EOF

# LAN with login: Caddy serves HTTPS with a self-signed certificate
# (tls internal) for this IP / LAN hostname - no public domain needed
DOMAIN=$DOMAIN
CADDYFILE=Caddyfile.lan
EOF
    elif [ "$DEPLOYMENT_TYPE" == "production" ]; then
        cat >> .env << EOF

# Domain name for HTTPS (production only)
DOMAIN=$DOMAIN
EOF
    fi

    if [ "$DEPLOYMENT_TYPE" == "production" ]; then
        cat >> .env << EOF

# Admin credentials (production only)
AUTH_USERNAME=$AUTH_USERNAME
AUTH_PASSWORD_HASH=${AUTH_PASSWORD_HASH//\$/\$\$}
EOF
    fi

    # Add common settings
    cat >> .env << EOF

# ============================================
# REQUIRED SETTINGS
# ============================================

# Encryption key for securing UniFi credentials
# WARNING: Do not change this key after initial setup or encrypted data will be lost
ENCRYPTION_KEY=$ENCRYPTION_KEY

# ============================================
# DATABASE SETTINGS
# ============================================

# Database URL (default uses SQLite in data/ directory)
DATABASE_URL=sqlite+aiosqlite:///./data/unifi_toolkit.db

# ============================================
# LOGGING
# ============================================

# Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_LEVEL=INFO

# ============================================
# UNIFI CONTROLLER SETTINGS
# ============================================
# These settings are OPTIONAL - you can configure them via the web UI instead.
# Web UI settings take precedence over these environment variables.

# UniFi Controller URL (include https:// or http://)
UNIFI_CONTROLLER_URL=

# Legacy Controllers: Use username + password
UNIFI_USERNAME=
UNIFI_PASSWORD=

# UniFi OS (UDM, UCG-Fiber, etc.): Use API key
# API keys can be generated in UniFi OS Settings → Admins → Create API Token
UNIFI_API_KEY=

# UniFi Site ID (default: "default")
UNIFI_SITE_ID=default

# SSL Verification (set to false for self-signed certificates)
UNIFI_VERIFY_SSL=false

# ============================================
# TOOL-SPECIFIC SETTINGS
# ============================================

# Wi-Fi Stalker: Device refresh interval in seconds
STALKER_REFRESH_INTERVAL=60
EOF

    print_success "Configuration saved to .env"
    echo ""

    # Create data directory if it doesn't exist
    if [ ! -d "data" ]; then
        mkdir -p data
        print_success "Created data directory"
    else
        print_success "Data directory already exists"
    fi

    # Set proper permissions for Docker (UID 1000 matches toolkit user in container).
    # Not on macOS: Docker Desktop / OrbStack write bind mounts as the Mac user,
    # so data/ must stay owned by that user - chowning it to 1000 locks it out.
    if [ "$(uname -s)" == "Darwin" ]; then
        if [ -n "$SUDO_USER" ]; then
            chown "$SUDO_USER" data .env 2>/dev/null || true
        fi
        print_success "macOS: data directory left owned by your user (Docker Desktop/OrbStack)"
    elif command -v docker &> /dev/null; then
        chown 1000:1000 data 2>/dev/null || chmod 755 data 2>/dev/null || true
        print_success "Set data directory permissions for Docker (UID 1000)"
    fi
    print_info "The data/ directory stores the SQLite database. The container"
    print_info "needs write access to /app/data (mapped from ./data on the host)."

    # Final instructions
    echo ""
    printf "${GREEN}=================================================================${NC}\n"
    printf "${GREEN}                     Setup Complete!${NC}\n"
    printf "${GREEN}=================================================================${NC}\n"
    echo ""

    if [ "$LAN_MODE" == true ]; then
        printf "${BOLD}Next Steps:${NC}\n"
        echo ""
        echo "  1. Start the application with Caddy (HTTPS + Auth):"
        printf "     ${CYAN}docker compose --profile production up -d${NC}\n"
        echo ""
        echo "  2. Access your toolkit at:"
        printf "     ${CYAN}https://%s${NC}\n" "$DOMAIN"
        echo "     Your browser will warn about the self-signed certificate the"
        echo "     first time - accept it once. (To remove the warning, trust"
        echo "     Caddy's root CA: docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt .)"
        echo ""
        echo "  3. Login with:"
        printf "     Username: ${CYAN}%s${NC}\n" "$AUTH_USERNAME"
        printf "     Password: ${CYAN}(the password you just set)${NC}\n"
        echo ""
        print_warning "Do not port-forward this to the internet. For remote access,"
        print_warning "use a VPN (WireGuard, Tailscale, UniFi VPN)."
    elif [ "$DEPLOYMENT_TYPE" == "production" ]; then
        printf "${BOLD}Next Steps:${NC}\n"
        echo ""
        printf "  1. Ensure DNS A record for ${CYAN}%s${NC} points to this server\n" "$DOMAIN"
        echo ""
        echo "  2. Ensure ports 80 and 443 are open in your firewall:"
        printf "     ${CYAN}sudo ufw allow 80/tcp${NC}\n"
        printf "     ${CYAN}sudo ufw allow 443/tcp${NC}\n"
        echo ""
        echo "  3. Start the application with Caddy (HTTPS + Auth):"
        printf "     ${CYAN}docker compose --profile production up -d${NC}\n"
        echo ""
        echo "  4. Access your toolkit at:"
        printf "     ${CYAN}https://%s${NC}\n" "$DOMAIN"
        echo ""
        echo "  5. Login with:"
        printf "     Username: ${CYAN}%s${NC}\n" "$AUTH_USERNAME"
        printf "     Password: ${CYAN}(the password you just set)${NC}\n"
        echo ""
        print_info "First startup may take a minute while Let's Encrypt issues your certificate."
        echo ""
        print_warning "Remember: Use VPN for multi-site deployments. Never expose"
        print_warning "UniFi controllers to the internet via port forwarding!"
    else
        printf "${BOLD}Next Steps:${NC}\n"
        echo ""
        echo "  1. Start the application:"
        printf "     ${CYAN}docker compose up -d${NC}\n"
        echo ""
        echo "     Or run directly with Python:"
        printf "     ${CYAN}pip install -r requirements.txt${NC}\n"
        printf "     ${CYAN}python run.py${NC}\n"
        echo ""
        echo "  2. Access your toolkit at:"
        printf "     ${CYAN}http://localhost:8000${NC}\n"
        echo ""
        print_warning "No authentication is configured for local deployment."
        print_warning "Keep this application on a trusted network only."
    fi

    echo ""
    echo "For help and documentation:"
    printf "  ${CYAN}https://github.com/CrosstalkSolutions/unifi-toolkit${NC}\n"
    echo ""
}

# Run main function
main
