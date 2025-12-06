# To install go
brew install go

# To clean artifacts
make clean

# to build artifacts for all OS type
make all

# Following artifacts will get build
  gitleaks-server_darwin_amd64
  gitleaks-server_darwin_arm64
  gitleaks-server_linux_amd64
  gitleaks-server_linux_arm64
  gitleaks-server_windows_amd64.exe
  gitleaks-server_windows_arm64.exe

# To run gitleaks server 
./<GITLEAKSE_SERVER_ARTIFACTNAME> server --addr :8080

# Test with CURL request for DIR
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/absolute/path/to/your/repo/or/dir",
    "timeoutSeconds": 60
  }'

# Test with CURL request for file
  curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/absolute/path/to/your/repo/or/file",
    "timeoutSeconds": 60
  }'
