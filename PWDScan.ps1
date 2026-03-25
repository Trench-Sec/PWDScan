#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Scans files for patterns that may indicate stored passwords or credentials,
    with strong filtering to suppress false positives.

.DESCRIPTION
    For every text file under ScanPath the script runs three detection passes:

      Pass 1 -- Keyword + value
        Finds lines where a credential label (password, secret, token, etc.)
        is followed by an actual value.  The value must:
          - Be at least 6 characters long
          - NOT be a common placeholder (<value>, your_password, changeme ...)
          - Contain at least two distinct character classes (letter+digit,
            letter+symbol, or digit+symbol) to exclude prose sentences
        Comment lines (#, //, REM, *) are skipped entirely.

      Pass 2 -- High-confidence structural patterns
        Matches credential-shaped strings that need no label context:
        AWS keys, GitHub/GitLab/Slack tokens, JWTs, PEM private key blocks,
        and password hash formats (bcrypt, argon2, scrypt).

      Pass 3 -- Hex / base64 blobs
        Long hex strings (32/40/64 hex chars) and base64 blobs (>= 40 chars)
        are flagged only when they appear on a line that also contains a
        credential keyword, to keep noise low.

    PRIVACY GUARANTEE
        Matched text is NEVER written to the report or the console.
        Only File Name, File Path, Match Reason, and Scan Timestamp are stored.

.PARAMETER ScanPath
    Root directory to scan.  Defaults to C:\

.PARAMETER OutputDir
    Directory to write the report.  Defaults to the script directory.

.PARAMETER Extensions
    File extensions to scan (without the dot).

.PARAMETER MaxFileSizeMB
    Skip files larger than this size.  Default: 10 MB.

.PARAMETER ExcludeDirs
    Directory name fragments to skip entirely.

.EXAMPLE
    .\Find-SensitiveFiles.ps1 -ScanPath $env:USERPROFILE -OutputDir "$env:USERPROFILE\Desktop"

.EXAMPLE
    .\Find-SensitiveFiles.ps1 -ScanPath C:\Projects -MaxFileSizeMB 5
#>

[CmdletBinding()]
param(
    [string]   $ScanPath      = 'C:\',
    [string]   $OutputDir     = $PSScriptRoot,
    [string[]] $Extensions    = @(
        'txt','log','ini','cfg','conf','config','env','properties',
        'xml','json','yaml','yml','toml','plist',
        'ps1','psm1','psd1','bat','cmd','sh',
        'py','rb','php','js','ts','cs','java','go','rs',
        'sql','htpasswd','netrc','rdp',
        'key','pem','ppk','asc',
        'md','rst','csv'
    ),
    [int]      $MaxFileSizeMB = 10,
    [string[]] $ExcludeDirs   = @(
        'Windows','$Recycle.Bin','WinSxS','SoftwareDistribution',
        'node_modules','.git','.svn','__pycache__','vendor',
        'Packages','AppData\Local\Microsoft'
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ===========================================================================
# CONSTANTS
# ===========================================================================

# Minimum character count for a value to be considered non-trivial
$MIN_VALUE_LEN = 6

# Regex that matches comment-only lines -- these are skipped for keyword pass
$CommentLineRx = [regex]'^\s*(#|//|/\*|\*|;|REM\s|<!--)'

# Placeholder values that should never trigger a finding.
# These are patterns for the VALUE portion of "keyword=VALUE" only.
$PlaceholderRx = [regex](
    '(?i)^(' +
    # Angle-bracket / curly-brace / percent templates
    '<[^>]{1,60}>|' +
    '\$\{[^}]{1,60}\}|' +
    '\$\([^)]{1,60}\)|' +
    '%\([^)]{1,60}\)[sd]|' +
    '\{\{[^}]{1,60}\}\}|' +
    # Common placeholder words (whole-value match)
    'your[-_]?password|your[-_]?secret|your[-_]?token|your[-_]?key|' +
    'my[-_]?password|example[-_]?password|' +
    'changeme|change_me|change-me|' +
    'placeholder|insert[-_]?here|enter[-_]?here|' +
    'todo|fixme|tbd|n/?a|none|null|nil|undefined|empty|blank|' +
    'true|false|yes|no|0|1|' +
    # Quoted-empty or very short fillers
    '""|' + "''|" +
    'xxxxxxxx+|' +
    '\*{4,}|' +
    # Documentation stand-ins
    'password123|pass123|test|demo|sample|dummy|' +
    'foo|bar|baz|qux|' +
    'abc123|123456|password|letmein|qwerty|admin|root|guest' +
    ')$'
)

# A value must contain characters from at least 2 of these classes to pass
# the complexity gate (reduces hits on plain English words / sentences)
function Get-CharClassCount ([string]$Value) {
    $count = 0
    if ($Value -cmatch '[A-Z]') { $count++ }
    if ($Value -cmatch '[a-z]') { $count++ }
    if ($Value -cmatch '[0-9]') { $count++ }
    if ($Value -cmatch '[^A-Za-z0-9]') { $count++ }
    return $count
}

# ===========================================================================
# PASS 1 -- KEYWORD PATTERNS
#   Each entry is a named hashtable: Label + ValueCaptureRegex.
#   The regex MUST have a named capture group called "val" for the value part.
#   Matching logic: label found -> extract val -> apply all quality gates.
# ===========================================================================

# Shared value capture: captures everything after the assignment operator
# up to end-of-line, trimming surrounding quotes.
# The outer pattern is built per-keyword below; $ValRx extracts the value.
$ValRx = [regex](
    '[:=>\s]+"?''?(?<val>[^\s"''<>{}\[\]]{' + $MIN_VALUE_LEN + ',100})"?''?\s*$'
)

$KeywordDefs = @(
    @{ Label = 'Keyword: password';        Pattern = '(?i)\b(password|passwd|passcode|pass_word)\b' },
    @{ Label = 'Keyword: pwd/pw';          Pattern = '(?i)\b(pwd|pw|pswd)\s*[:=]' },
    @{ Label = 'Keyword: secret';          Pattern = '(?i)\b(secret)\b' },
    @{ Label = 'Keyword: api_key';         Pattern = '(?i)\b(api[_\-]?key|apikey|access[_\-]?key)\b' },
    @{ Label = 'Keyword: auth_token';      Pattern = '(?i)\b(auth[_\-]?token|authtoken|bearer)\b' },
    @{ Label = 'Keyword: db_password';     Pattern = '(?i)\b(db[_\-]?pass|database[_\-]?pass|mysql[_\-]?pwd|pg[_\-]?pass)\b' },
    @{ Label = 'Keyword: connection_str';  Pattern = '(?i)\b(connection[_\-]?string|connstr|jdbc[_\-]?url)\b' },
    @{ Label = 'Keyword: cloud_secret';    Pattern = '(?i)\b(aws[_\-]?secret|azure[_\-]?client[_\-]?secret|gcp[_\-]?key|gcloud[_\-]?key)\b' },
    @{ Label = 'Keyword: credential';      Pattern = '(?i)\b(credential[s]?|cred[s]?)\s*[:=]' },
    @{ Label = 'Keyword: private_key';     Pattern = '(?i)\b(private[_\-]?key|privkey)\b' },
    @{ Label = 'PS: SecureString';         Pattern = '(?i)ConvertTo-SecureString\s' },
    @{ Label = 'PS: PSCredential';         Pattern = '(?i)\[System\.Management\.Automation\.PSCredential\]|New-Object.*PSCredential' },
    @{ Label = 'Keyword: net_use_cred';    Pattern = '(?i)(net\s+use\s+.*\s+/user:|runas\s+/user:)' }
)

# Pre-compile keyword patterns
$CompiledKeywords = foreach ($kd in $KeywordDefs) {
    try {
        [PSCustomObject]@{
            Label  = $kd.Label
            Regex  = [regex]::new($kd.Pattern, 'IgnoreCase,Multiline', [timespan]::FromSeconds(2))
        }
    } catch { }
}

# ===========================================================================
# PASS 2 -- HIGH-CONFIDENCE STRUCTURAL PATTERNS (no label context needed)
# ===========================================================================

$StructuralDefs = @(
    @{ Label = 'AWS access key ID';     Pattern = '\bAKIA[0-9A-Z]{16}\b' },
    @{ Label = 'AWS secret key';        Pattern = '(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])' },
    @{ Label = 'GitHub token';          Pattern = '\bgh[pousr]_[A-Za-z0-9]{36,}\b' },
    @{ Label = 'GitLab token';          Pattern = '\bglpat-[A-Za-z0-9\-_]{20,}\b' },
    @{ Label = 'Slack token';           Pattern = '\bxox[baprs]-[0-9A-Za-z\-]{10,72}\b' },
    @{ Label = 'JWT token';             Pattern = '\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b' },
    @{ Label = 'PEM private key block'; Pattern = '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----' },
    @{ Label = 'bcrypt hash';           Pattern = '\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}' },
    @{ Label = 'argon2 hash';           Pattern = '\$argon2(i|d|id)\$v=\d+' },
    @{ Label = 'scrypt hash';           Pattern = '\$scrypt\$ln=\d+' }
)

$CompiledStructural = foreach ($sd in $StructuralDefs) {
    try {
        [PSCustomObject]@{
            Label = $sd.Label
            Regex = [regex]::new($sd.Pattern, 'IgnoreCase,Multiline', [timespan]::FromSeconds(2))
        }
    } catch { }
}

# ===========================================================================
# PASS 3 -- HEX / BASE64 BLOBS  (only on lines that also have a keyword)
#   Requiring a co-located keyword dramatically reduces noise from hashes
#   used in non-credential contexts (checksums, IDs, file hashes, etc.)
# ===========================================================================

$BlobKeywordRx = [regex]'(?i)\b(password|passwd|secret|key|token|auth|cred|hash)\b'

$BlobPatterns = @(
    @{ Label = 'SHA-256-length hex (with cred keyword)'; Pattern = '\b[0-9a-fA-F]{64}\b' },
    @{ Label = 'SHA-1-length hex (with cred keyword)';   Pattern = '\b[0-9a-fA-F]{40}\b' },
    @{ Label = 'MD5-length hex (with cred keyword)';     Pattern = '\b[0-9a-fA-F]{32}\b' },
    @{ Label = 'Base64 blob >= 40 chars (with cred keyword)';
       Pattern = '(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])' }
)

$CompiledBlobs = foreach ($bp in $BlobPatterns) {
    try {
        [PSCustomObject]@{
            Label = $bp.Label
            Regex = [regex]::new($bp.Pattern, 'IgnoreCase,Multiline', [timespan]::FromSeconds(2))
        }
    } catch { }
}

# ===========================================================================
# FILE SCANNING FUNCTION
# ===========================================================================

function Test-FileForMatches ([System.IO.FileInfo]$File) {
    <#
        Returns a match-reason string, or $null if no credible credential found.
        The matched VALUE is never returned, stored, or printed.
    #>

    # Read file; bail on binary (null bytes) or read errors
    try {
        $raw = [System.IO.File]::ReadAllText($File.FullName, [System.Text.Encoding]::UTF8)
    } catch { return $null }
    if ($raw -match '\x00') { return $null }

    $lines = $raw -split "`r?`n"

    foreach ($line in $lines) {

        # Skip excessively long lines (minified JS, binary-ish data)
        if ($line.Length -gt 2000) { continue }

        # ---------- PASS 1: Keyword + value quality gates ----------
        if (-not $CommentLineRx.IsMatch($line)) {

            foreach ($kw in $CompiledKeywords) {
                try {
                    if (-not $kw.Regex.IsMatch($line)) { continue }

                    # Extract the value that follows the assignment operator
                    $valMatch = $ValRx.Match($line)
                    if (-not $valMatch.Success) { continue }

                    $val = $valMatch.Groups['val'].Value.Trim()

                    # Gate 1: minimum length (already enforced by regex quantifier,
                    #         but double-check after trimming quotes)
                    if ($val.Length -lt $MIN_VALUE_LEN) { continue }

                    # Gate 2: reject placeholder values
                    if ($PlaceholderRx.IsMatch($val)) { continue }

                    # Gate 3: value must span at least 2 character classes
                    if ((Get-CharClassCount $val) -lt 2) { continue }

                    # Gate 4: reject if the value looks like a plain English phrase
                    #         (lots of spaces = probably a description, not a secret)
                    if (($val -split '\s+').Count -gt 3) { continue }

                    return $kw.Label   # Report label only -- value discarded
                }
                catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { continue }
            }
        }

        # ---------- PASS 2: High-confidence structural patterns ----------
        foreach ($sp in $CompiledStructural) {
            try {
                if ($sp.Regex.IsMatch($line)) { return $sp.Label }
            }
            catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { continue }
        }

        # ---------- PASS 3: Hex / base64 blobs (keyword co-location required) ----------
        try {
            if ($BlobKeywordRx.IsMatch($line)) {
                foreach ($bp in $CompiledBlobs) {
                    try {
                        if ($bp.Regex.IsMatch($line)) { return $bp.Label }
                    }
                    catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { continue }
                }
            }
        }
        catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { continue }
    }

    return $null
}

# ===========================================================================
# FILE DISCOVERY
# ===========================================================================

$MaxFileBytes = $MaxFileSizeMB * 1MB

function Should-Skip ([System.IO.FileInfo]$File) {
    if ($File.Length -gt $MaxFileBytes) { return $true }
    foreach ($seg in $ExcludeDirs) {
        if ($File.FullName -like "*\$seg\*") { return $true }
    }
    return $false
}

Write-Host ""
Write-Host ("-" * 65) -ForegroundColor Cyan
Write-Host "  Credential Pattern Scanner (low false-positive mode)" -ForegroundColor White
Write-Host ("-" * 65) -ForegroundColor Cyan
Write-Host "  Scan root : $ScanPath"
Write-Host "  Max size  : $MaxFileSizeMB MB per file"
Write-Host "  Min value : $MIN_VALUE_LEN chars, 2+ char classes, non-placeholder"
Write-Host ""
Write-Host "  Building file list..." -ForegroundColor Yellow

$extFilter = $Extensions | ForEach-Object { "*.$_" }
$allFiles  = Get-ChildItem -Path $ScanPath -Recurse -File `
                 -Include $extFilter -Force -ErrorAction SilentlyContinue |
             Where-Object { -not (Should-Skip $_) }

$totalFiles = @($allFiles).Count
Write-Host "  Files to scan : $totalFiles" -ForegroundColor Yellow
Write-Host ""

# ===========================================================================
# MAIN SCAN LOOP
# ===========================================================================

$findings  = [System.Collections.Generic.List[PSCustomObject]]::new()
$scanned   = 0
$hitCount  = 0
$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

foreach ($file in $allFiles) {
    $scanned++
    if ($scanned % 200 -eq 0) {
        Write-Host ("  Scanned {0,6} / {1,6}  |  Findings so far: {2}" `
            -f $scanned, $totalFiles, $hitCount) -ForegroundColor DarkGray
    }

    $reason = Test-FileForMatches $file
    if ($reason) {
        $hitCount++
        # Only name, path, and category label are stored -- never the secret value
        $findings.Add([PSCustomObject]@{
            'File Name'      = $file.Name
            'File Path'      = $file.FullName
            'Match Reason'   = $reason
            'Scan Timestamp' = $timestamp
        })
    }
}

Write-Host ""
Write-Host ("  Scan complete.  Scanned: $scanned  |  Findings: $hitCount") `
    -ForegroundColor Cyan

# ===========================================================================
# EXPORT: XLSX via Excel COM, fall back to CSV
# ===========================================================================

$stamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
$xlsxPath = Join-Path $OutputDir "CredentialScan_$stamp.xlsx"
$csvPath  = Join-Path $OutputDir "CredentialScan_$stamp.csv"

function Export-ToXlsx (
    [System.Collections.Generic.List[PSCustomObject]]$Data,
    [string]$Path
) {
    try {
        $xl  = New-Object -ComObject Excel.Application -ErrorAction Stop
        $xl.Visible       = $false
        $xl.DisplayAlerts = $false

        $wb = $xl.Workbooks.Add()
        $ws = $wb.Worksheets.Item(1)
        $ws.Name = 'Credential Scan'

        # Header row
        $headers = @('File Name','File Path','Match Reason','Scan Timestamp')
        for ($c = 0; $c -lt $headers.Count; $c++) {
            $cell = $ws.Cells.Item(1, $c + 1)
            $cell.Value2           = $headers[$c]
            $cell.Font.Bold        = $true
            $cell.Font.Name        = 'Arial'
            $cell.Font.Size        = 10
            $cell.Interior.Color   = 0x2E4057
            $cell.Font.Color       = 0xFFFFFF
        }

        # Data rows
        $row = 2
        foreach ($entry in $Data) {
            $ws.Cells.Item($row, 1).Value2 = $entry.'File Name'
            $ws.Cells.Item($row, 2).Value2 = $entry.'File Path'
            $ws.Cells.Item($row, 3).Value2 = $entry.'Match Reason'
            $ws.Cells.Item($row, 4).Value2 = $entry.'Scan Timestamp'
            if ($row % 2 -eq 0) {
                for ($c = 1; $c -le 4; $c++) {
                    $ws.Cells.Item($row, $c).Interior.Color = 0xF2F2F2
                }
            }
            $row++
        }

        # Column widths
        $ws.Columns.Item(1).ColumnWidth = 36
        $ws.Columns.Item(2).ColumnWidth = 72
        $ws.Columns.Item(3).ColumnWidth = 36
        $ws.Columns.Item(4).ColumnWidth = 20

        # Font for data
        if ($Data.Count -gt 0) {
            $rng = $ws.Range($ws.Cells.Item(2,1), $ws.Cells.Item($row - 1, 4))
            $rng.Font.Name = 'Arial'
            $rng.Font.Size = 9
        }

        # Auto-filter, freeze pane, summary
        $ws.Rows.Item(1).AutoFilter() | Out-Null
        $ws.Application.ActiveWindow.SplitRow  = 1
        $ws.Application.ActiveWindow.FreezePanes = $true

        $sumRow = $row + 1
        $sumCell = $ws.Cells.Item($sumRow, 1)
        $sumCell.Value2    = "Total findings: $($Data.Count)"
        $sumCell.Font.Bold = $true
        $sumCell.Font.Name = 'Arial'

        $wb.SaveAs($Path, 51)   # 51 = xlOpenXMLWorkbook
        $wb.Close($false)
        $xl.Quit()
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($xl) | Out-Null
        return $true
    } catch {
        return $false
    }
}

if ($findings.Count -eq 0) {
    Write-Host ""
    Write-Host "  No credential patterns found. No report generated." -ForegroundColor Green
} else {
    $ok = Export-ToXlsx $findings $xlsxPath
    if ($ok -and (Test-Path $xlsxPath)) {
        Write-Host "  Report saved (XLSX) -> $xlsxPath" -ForegroundColor Green
    } else {
        $findings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "  Excel not available -- report saved (CSV) -> $csvPath" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "  NOTE: Matched text has NOT been stored in the report." -ForegroundColor DarkGray
    Write-Host "        Only file names, paths, and match categories are recorded." -ForegroundColor DarkGray
}
Write-Host ""
