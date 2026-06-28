#!/bin/bash
# AlertMesh NIDS - Installation Script for Linux/macOS
# Network-Based Intrusion Alert System with Advanced IP Logging for Corporate Offices in Nepal

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

echo "=========================================="
echo "  AlertMesh NIDS - Installation Script"
echo "=========================================="
echo ""

# Check Python
print_info "Checking Python..."
if command -v python3 &>/dev/null; then
    PYTHON_CMD="python3"
elif command -v python &>/dev/null; then
    PYTHON_CMD="python"
else
    print_error "Python not found. Please install Python 3.8 or higher."
    exit 1
fi
print_success "Python found: $($PYTHON_CMD --version)"

# Check if virtual environment exists
print_info "Checking virtual environment..."
if [ -d "venv" ]; then
    print_warning "Virtual environment already exists"
    read -p "Recreate virtual environment? (y/n): " recreate
    if [[ $recreate == "y" || $recreate == "Y" ]]; then
        print_info "Removing existing virtual environment..."
        rm -rf venv
        $PYTHON_CMD -m venv venv
        print_success "Virtual environment recreated"
    else
        print_success "Using existing virtual environment"
    fi
else
    print_info "Creating virtual environment..."
    $PYTHON_CMD -m venv venv
    print_success "Virtual environment created"
fi

# Activate virtual environment
print_info "Activating virtual environment..."
source venv/bin/activate
print_success "Virtual environment activated"

# Upgrade pip
print_info "Upgrading pip..."
python -m pip install --upgrade pip setuptools wheel >/dev/null 2>&1
print_success "Pip upgraded"

# Install dependencies
print_info "Installing Python dependencies..."
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    print_error "Failed to install dependencies"
    exit 1
fi
print_success "Dependencies installed"

# Create .env file if it doesn't exist
print_info "Checking environment configuration..."
if [ ! -f "src/.env" ]; then
    if [ -f "src/.env.example" ]; then
        cp src/.env.example src/.env
        print_success ".env file created from .env.example"
        print_warning "Please edit src/.env with your actual credentials"
    else
        print_info "Creating basic .env file..."
        cat > src/.env << EOL
SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(24))')
FLASK_ENV=development
FLASK_DEBUG=False
USERNAME=change_this_admin_user
PASSWORD=change_this_admin_password
SESSION_COOKIE_SECURE=False
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Lax
LOGIN_MAX_ATTEMPTS=5
LOGIN_RATE_LIMIT_SECONDS=300
TRUST_PROXY_HEADERS=false
EMAIL_ENABLED=false
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_FROM=
SMTP_TO=
ALERT_COOLDOWN=60
MAX_HISTORY=2000
INCLUDE_DISCOVERY_TRAFFIC=false
DASHBOARD_PACKET_CAPTURE_ENABLED=true
PACKET_EXPORTS_ENABLED=false
DASHBOARD_TIMEZONE=Asia/Kathmandu
PROTECTED_NETWORKS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
IGNORE_SOURCE_IPS=
TRUSTED_SOURCE_IPS=
ALERT_REJECT_TRUSTED_SOURCES=true
ALERT_REQUIRE_PROTECTED_DESTINATION=true
ALERT_MIN_CONFIDENCE=55
ALERT_DEDUP_SECONDS=120
ALERT_STRICT_MODE=false
ALERT_ALLOWED_SOURCES=python,snort
ALERT_ALLOWED_SNORT_SID_RANGES=9000001-9000013,9000024,9000026-9000029
ALERT_ALLOW_LOW_CONFIDENCE=false
ICMP_ALERT_THRESHOLD=5
ICMP_ALERT_WINDOW=10
EXPOSED_SERVICE_ALERT_THRESHOLD=3
EXPOSED_SERVICE_ALERT_WINDOW=60
TRACKER_CLEANUP_SECONDS=300
GEOLOCATION_ENABLED=false
WEBSITES_PORT=5001
ALERTMESH_DB_PATH=alertmesh.db
ALERTMESH_DB_BACKEND=sqlite
MONGODB_URI=mongodb://localhost:27017
MONGODB_DATABASE=alertmesh
ALERT_RETENTION_DAYS=30
EOL
        print_success ".env file created"
        print_warning "Please edit src/.env with your actual credentials"
    fi
else
    print_success ".env file already exists"
fi

# Create logs directory
print_info "Creating logs directory..."
mkdir -p src/logs
print_success "Logs directory created"

# Make Linux/macOS helper scripts executable
print_info "Setting executable permissions on shell helpers..."
chmod +x src/start_*_linux.sh 2>/dev/null || true
print_success "Shell helpers are ready"

# Check for packet capture capabilities (libpcap)
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    print_info "Checking for libpcap (Linux)..."
    if ldconfig -p | grep -q libpcap; then
        print_success "libpcap found"
    else
        print_warning "libpcap not found. Live capture may fail."
        echo "   Install it with: sudo apt-get install libpcap-dev"
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    print_success "Running on macOS (libpcap is usually pre-installed)"
fi

# Print summary
echo ""
echo "=========================================="
echo "  Installation Complete!"
echo "=========================================="
echo ""
print_success "Virtual environment: venv/"
print_success "Dependencies       : Installed"
print_success "Configuration      : src/.env"
print_success "Logs directory     : src/logs/"
echo ""
echo "Next Steps:"
echo ""
echo "  1. Configure email alerts:"
echo "     - Open src/.env"
echo "     - Set EMAIL_ENABLED=true and SMTP_* values"
echo "     - Run: python src/test_email.py"
echo ""
echo "  2. Activate virtual environment:"
echo "     source venv/bin/activate"
echo ""
echo "  3. Start the NIDS engine (in one terminal):"
echo "     cd src && sudo ./start_python_nids_linux.sh"
echo ""
echo "  4. Start the dashboard (in another terminal):"
echo "     cd src && ./start_dashboard_linux.sh"
echo ""
print_info "Access the dashboard at: http://localhost:5001"
print_info "Dashboard login is read from src/.env (USERNAME and PASSWORD)."
echo ""
print_warning "Live packet capture usually requires sudo/root privileges."
print_warning "Without root rights, no packet capture will run."
echo ""
