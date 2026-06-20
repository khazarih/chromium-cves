#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_step() {
    echo -e "\n${GREEN}=== $1 ===${NC}"
}

# Check prerequisites
check_prerequisites() {
    print_step "Checking prerequisites"
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    print_status "Docker found"
    
    # Check Docker Compose
    if ! docker compose version &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    print_status "Docker Compose found"
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        print_error "Python3 is not installed. Please install Python 3.10+ first."
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    if (( $(echo "$PYTHON_VERSION < 3.10" | bc -l) )); then
        print_error "Python 3.10+ is required. Found: $PYTHON_VERSION"
        exit 1
    fi
    print_status "Python $PYTHON_VERSION found"
    
    # Check uv (optional but recommended)
    if command -v uv &> /dev/null; then
        print_status "uv found (fast package manager)"
    else
        print_warning "uv not found, will use pip (slower)"
    fi
}

# Clone cvelistV5 if not exists
clone_cvelist() {
    print_step "Setting up cvelistV5 data"
    
    if [ -d "cvelistV5" ]; then
        print_status "cvelistV5 directory already exists"
    else
        print_status "Cloning cvelistV5 repository (this may take a while)..."
        git clone --depth 1 https://github.com/CVEProject/cvelistV5.git
        print_status "cvelistV5 cloned successfully"
    fi
}

# Install Python dependencies
install_dependencies() {
    print_step "Installing Python dependencies"
    
    if command -v uv &> /dev/null; then
        print_status "Using uv for fast installation..."
        uv sync
    else
        print_status "Using pip for installation..."
        pip install -e .
    fi
    
    print_status "Dependencies installed"
}

# Start ChromaDB
start_chromadb() {
    print_step "Starting ChromaDB"
    
    # Check if ChromaDB is already running
    if docker ps | grep -q chromium-cves-chroma; then
        print_status "ChromaDB is already running"
    else
        print_status "Starting ChromaDB container..."
        docker compose up -d
        
        # Wait for ChromaDB to be ready
        print_status "Waiting for ChromaDB to be ready..."
        for i in {1..30}; do
            if curl -s http://localhost:8001/api/v2/heartbeat > /dev/null 2>&1; then
                print_status "ChromaDB is ready"
                break
            fi
            if [ $i -eq 30 ]; then
                print_error "ChromaDB failed to start within 30 seconds"
                exit 1
            fi
            sleep 1
        done
    fi
}

# Run the pipeline
run_pipeline() {
    print_step "Running CVE pipeline"
    
    # Stage 1: Collect CVEs
    echo ""
    print_status "Stage 1/3: Collecting Chromium CVEs..."
    python3 collector.py
    
    # Stage 2: Resolve bug IDs to commits
    echo ""
    print_status "Stage 2/3: Resolving bug IDs to commits (this may take a while)..."
    python3 resolver.py
    
    # Stage 3: Extract patched code
    echo ""
    print_status "Stage 3/3: Extracting patched code..."
    python3 extractor.py
    
    print_status "Pipeline completed!"
}

# Print summary
print_summary() {
    print_step "Setup Complete!"
    
    echo ""
    echo "Chromium CVE RAG is ready!"
    echo ""
    echo "Collections:"
    echo "  - chromium_cves: CVE metadata and descriptions"
    echo "  - chromium_patches: Patched code with context"
    echo "  - chromium_experiments: Agent experiment history"
    echo "  - chromium_mistakes: Lessons learned"
    echo ""
    echo "Usage:"
    echo "  python3 query.py cves 'sandbox escape' --severity CRITICAL"
    echo "  python3 query.py patches 'heap overflow' --lang cc"
    echo "  python3 query.py show CVE-2022-3075"
    echo ""
    echo "ChromaDB: http://localhost:8001"
    echo ""
}

# Main execution
main() {
    echo "Chromium CVE RAG Setup"
    echo "====================="
    
    check_prerequisites
    clone_cvelist
    install_dependencies
    start_chromadb
    run_pipeline
    print_summary
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-pipeline)
            SKIP_PIPELINE=1
            shift
            ;;
        --skip-clone)
            SKIP_CLONE=1
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run with options
if [ "$SKIP_PIPELINE" = "1" ]; then
    echo "Chromium CVE RAG Setup (skipping pipeline)"
    echo "==========================================="
    check_prerequisites
    clone_cvelist
    install_dependencies
    start_chromadb
    echo ""
    print_status "Setup complete (pipeline skipped)"
    print_status "Run 'python3 collector.py && python3 resolver.py && python3 extractor.py' to populate data"
else
    main
fi
