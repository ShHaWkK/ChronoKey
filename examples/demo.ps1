param(
    [string]$Label = "chronokey-demo",
    [string]$IssuerAddress = "http://127.0.0.1:8080/redeem"
)

if (-not (Get-Command chronokey -ErrorAction SilentlyContinue)) {
    Write-Error "chronokey binary not found in PATH"
    exit 1
}

if (-not (Get-Command chronokey-issuer -ErrorAction SilentlyContinue)) {
    Write-Error "chronokey-issuer binary not found in PATH"
    exit 1
}

if (-not $env:CHRONOKEY_HMAC_SECRET) {
    Write-Error "Set CHRONOKEY_HMAC_SECRET before running"
    exit 1
}

$work = New-Item -ItemType Directory -Path ([System.IO.Path]::GetTempPath()) -Name ("chronokey-" + [System.Guid]::NewGuid())
$configPath = Join-Path $work.FullName "issuer.toml"
$tokenPath = Join-Path $work.FullName "token.txt"
$certPath = Join-Path $env:USERPROFILE ".ssh/${Label}-cert.pub"

@"
ca_private_key = "${env:USERPROFILE}\.chronokey\ca_ed25519"
default_validity = "+30m"
bind_addr = "127.0.0.1:8080"
"@ | Out-File -FilePath $configPath -Encoding UTF8

Write-Host "[+] Initialising CA"
try { chronokey init-ca } catch {}

Write-Host "[+] Generating SSH keypair"
chronokey keygen $Label

Write-Host "[+] Issuing token"
$tempToken = chronokey token issue --user $env:USERNAME --ttl 30m --attrs "principals=$($env:USERNAME)"
$tempToken | Out-File -FilePath $tokenPath -Encoding UTF8

Write-Host "[+] Starting issuer"
$issuer = Start-Process chronokey-issuer -ArgumentList "--config", "$configPath" -NoNewWindow -PassThru
Start-Sleep -Seconds 2

try {
    Write-Host "[+] Redeeming token"
    chronokey redeem --token ($tempToken.Trim()) --pubkey "$env:USERPROFILE/.ssh/${Label}.pub" --issuer $IssuerAddress --out $certPath
    Write-Host "Certificate written to $certPath"
}
finally {
    if ($issuer -and -not $issuer.HasExited) {
        $issuer.Kill()
    }
}
