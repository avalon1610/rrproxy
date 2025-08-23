# Certificate Generation Script for RRProxy (Windows PowerShell)
# This script generates self-signed certificates for HTTPS proxy functionality

param(
    [string]$OutputPath = "",
    [int]$ValidityDays = 365,
    [string]$Subject = "/C=US/ST=CA/L=San Francisco/O=RRProxy/OU=Development/CN=localhost"
)

# Set error action preference
$ErrorActionPreference = "Stop"

Write-Host "🔐 Generating certificates for RRProxy..." -ForegroundColor Green
Write-Host ""

# Determine output path
if ($OutputPath -eq "") {
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $ProjectRoot = Split-Path -Parent $ScriptDir
    $OutputPath = $ProjectRoot
}

Write-Host "📁 Project root: $ProjectRoot" -ForegroundColor Cyan
Write-Host "📁 Certificates will be saved to: $OutputPath" -ForegroundColor Cyan
Write-Host ""

# Check if OpenSSL is available (try different common locations)
$OpenSSLPaths = @(
    "openssl",
    "C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
    "C:\OpenSSL-Win64\bin\openssl.exe",
    "C:\Program Files (x86)\OpenSSL-Win32\bin\openssl.exe",
    "C:\OpenSSL-Win32\bin\openssl.exe"
)

$OpenSSLPath = $null
foreach ($path in $OpenSSLPaths) {
    try {
        $null = Get-Command $path -ErrorAction Stop
        $OpenSSLPath = $path
        break
    } catch {
        continue
    }
}

if (-not $OpenSSLPath) {
    Write-Host "❌ OpenSSL not found. Please install OpenSSL first:" -ForegroundColor Red
    Write-Host "   1. Download from: https://slproweb.com/products/Win32OpenSSL.html" -ForegroundColor Yellow
    Write-Host "   2. Or install via Chocolatey: choco install openssl" -ForegroundColor Yellow
    Write-Host "   3. Or install via Windows Package Manager: winget install OpenSSL.OpenSSL" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "🔄 Alternative: Use Windows built-in certificate generation..." -ForegroundColor Cyan
    
    # Fallback to Windows built-in certificate generation
    try {
        Write-Host "📋 Using Windows built-in certificate generation" -ForegroundColor Yellow
        
        # Backup existing certificates
        $BackupDir = "$OutputPath\cert_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        if ((Test-Path "$OutputPath\cert.pem") -or (Test-Path "$OutputPath\key.pem")) {
            Write-Host "🔄 Backing up existing certificates to: $BackupDir" -ForegroundColor Cyan
            New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
            
            if (Test-Path "$OutputPath\cert.pem") { Copy-Item "$OutputPath\cert.pem" $BackupDir }
            if (Test-Path "$OutputPath\key.pem") { Copy-Item "$OutputPath\key.pem" $BackupDir }
            if (Test-Path "$OutputPath\cert.crt") { Copy-Item "$OutputPath\cert.crt" $BackupDir }
            
            Write-Host "✅ Backup completed" -ForegroundColor Green
        }
        
        # Generate certificate using Windows PowerShell
        Write-Host "📜 Generating self-signed certificate using Windows crypto..." -ForegroundColor Cyan
        
        $cert = New-SelfSignedCertificate -DnsName "localhost", "*.localhost" -CertStoreLocation "cert:\LocalMachine\My" -NotAfter (Get-Date).AddDays($ValidityDays) -Subject $Subject
        
        # Export certificate to PEM format
        $certPath = "$OutputPath\cert.crt"
        $pemCertPath = "$OutputPath\cert.pem"
        
        Export-Certificate -Cert $cert -FilePath $certPath -Type CERT | Out-Null
        
        # Convert to PEM format (Base64 with headers)
        $certBytes = [System.IO.File]::ReadAllBytes($certPath)
        $base64Cert = [System.Convert]::ToBase64String($certBytes)
        $pemCert = "-----BEGIN CERTIFICATE-----`n"
        for ($i = 0; $i -lt $base64Cert.Length; $i += 64) {
            $pemCert += $base64Cert.Substring($i, [Math]::Min(64, $base64Cert.Length - $i)) + "`n"
        }
        $pemCert += "-----END CERTIFICATE-----`n"
        [System.IO.File]::WriteAllText($pemCertPath, $pemCert)
        
        # Export private key (this is more complex and requires manual steps)
        Write-Host "⚠️  Note: Private key export requires manual steps:" -ForegroundColor Yellow
        Write-Host "   1. Open 'certmgr.msc' (Certificate Manager)" -ForegroundColor Yellow
        Write-Host "   2. Navigate to Personal > Certificates" -ForegroundColor Yellow
        Write-Host "   3. Find the certificate with subject: $Subject" -ForegroundColor Yellow
        Write-Host "   4. Right-click > All Tasks > Export..." -ForegroundColor Yellow
        Write-Host "   5. Choose 'Yes, export the private key'" -ForegroundColor Yellow
        Write-Host "   6. Save as PFX, then convert to PEM using OpenSSL" -ForegroundColor Yellow
        
        Write-Host "✅ Certificate generated (manual key export needed)" -ForegroundColor Green
        
        # Clean up certificate from store
        Remove-Item "cert:\LocalMachine\My\$($cert.Thumbprint)" -Force
        
        return
    } catch {
        Write-Host "❌ Failed to generate certificate: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

Write-Host "✅ Found OpenSSL at: $OpenSSLPath" -ForegroundColor Green

# Certificate configuration
$KeySize = 2048

Write-Host "📋 Certificate configuration:" -ForegroundColor Cyan
Write-Host "   Subject: $Subject" -ForegroundColor White
Write-Host "   Key size: $KeySize bits" -ForegroundColor White
Write-Host "   Validity: $ValidityDays days" -ForegroundColor White
Write-Host ""

# Backup existing certificates if they exist
$BackupDir = "$OutputPath\cert_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
if ((Test-Path "$OutputPath\cert.pem") -or (Test-Path "$OutputPath\key.pem")) {
    Write-Host "🔄 Backing up existing certificates to: $BackupDir" -ForegroundColor Cyan
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    
    if (Test-Path "$OutputPath\cert.pem") { Copy-Item "$OutputPath\cert.pem" $BackupDir }
    if (Test-Path "$OutputPath\key.pem") { Copy-Item "$OutputPath\key.pem" $BackupDir }
    if (Test-Path "$OutputPath\cert.crt") { Copy-Item "$OutputPath\cert.crt" $BackupDir }
    
    Write-Host "✅ Backup completed" -ForegroundColor Green
}

try {
    # Generate private key
    Write-Host "🔑 Generating private key..." -ForegroundColor Cyan
    & $OpenSSLPath genrsa -out "$OutputPath\key.pem" $KeySize
    if ($LASTEXITCODE -ne 0) { throw "Failed to generate private key" }

    # Create extensions file for Subject Alternative Names
    $ExtFile = "$OutputPath\cert.ext"
    @"
[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
IP.1 = 127.0.0.1
IP.2 = ::1
"@ | Out-File -FilePath $ExtFile -Encoding ASCII

    # Generate certificate signing request
    Write-Host "📝 Generating certificate signing request..." -ForegroundColor Cyan
    & $OpenSSLPath req -new -key "$OutputPath\key.pem" -out "$OutputPath\cert.csr" -subj $Subject
    if ($LASTEXITCODE -ne 0) { throw "Failed to generate CSR" }

    # Generate self-signed certificate
    Write-Host "📜 Generating self-signed certificate..." -ForegroundColor Cyan
    & $OpenSSLPath x509 -req -in "$OutputPath\cert.csr" -signkey "$OutputPath\key.pem" -out "$OutputPath\cert.pem" -days $ValidityDays -extensions v3_req -extfile $ExtFile
    if ($LASTEXITCODE -ne 0) { throw "Failed to generate certificate" }

    # Also create a .crt version for compatibility
    Copy-Item "$OutputPath\cert.pem" "$OutputPath\cert.crt"

    # Clean up temporary files
    Remove-Item "$OutputPath\cert.csr" -ErrorAction SilentlyContinue
    Remove-Item $ExtFile -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "✅ Certificates generated successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "📁 Generated files:" -ForegroundColor Cyan
    Write-Host "   🔑 Private key: $OutputPath\key.pem" -ForegroundColor White
    Write-Host "   📜 Certificate: $OutputPath\cert.pem" -ForegroundColor White
    Write-Host "   📜 Certificate (copy): $OutputPath\cert.crt" -ForegroundColor White
    Write-Host ""
    
    # Display certificate information
    Write-Host "📋 Certificate information:" -ForegroundColor Cyan
    & $OpenSSLPath x509 -in "$OutputPath\cert.pem" -text -noout | Select-String -Pattern "Subject:", "Not Before", "Not After" | ForEach-Object { Write-Host "   $($_.Line.Trim())" -ForegroundColor White }
    
    Write-Host ""
    Write-Host "🔍 To verify the certificate:" -ForegroundColor Yellow
    Write-Host "   $OpenSSLPath x509 -in `"$OutputPath\cert.pem`" -text -noout" -ForegroundColor White
    Write-Host ""
    Write-Host "⚠️  Note: These are self-signed certificates for development use only." -ForegroundColor Yellow
    Write-Host "   For production, use certificates from a trusted Certificate Authority." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "🚀 You can now run RRProxy with HTTPS support!" -ForegroundColor Green

} catch {
    Write-Host "❌ Error generating certificates: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
