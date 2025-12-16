# ============================================
param(
    [string]$AccessLevel = ""
)
# ============================================
# SUITE IT PROFESSIONAL - VERSIÓN 5.0 FINAL
# ============================================
# Autor: Andrés Suárez (Andrachox)
# País: Colombia
# Contacto: xxxxxxxxxxxxxxxxx
# Licencia: MIT License (Open Source)
# Versión: 5.0.0-final
# Fecha: 2025-12-15
# Compatibilidad: PowerShell 5.1+ / 7+
# Sistema: Windows 10, 11, Server 2016+
# ============================================
# © 2025 Andrachox. Todos los derechos reservados.
# No puede ser usado bajo términos ilegales
# ============================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ============================================
# CARGA DE DEPENDENCIAS
# ============================================
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName Microsoft.VisualBasic


# ============================================
# CONFIGURACIÓN LOGIN & ESTILOS (Dark Mode)
# ============================================
$ColorBack = [System.Drawing.Color]::FromArgb(30, 30, 30)
$ColorPanel = [System.Drawing.Color]::FromArgb(45, 45, 48)
$ColorText = [System.Drawing.Color]::White
$ColorButton = [System.Drawing.Color]::FromArgb(0, 122, 204)
$ColorInput = [System.Drawing.Color]::FromArgb(60, 60, 60)

# ============================================
# CONFIGURACIÓN
# ============================================

$script:AuthorInfo = @{
    Name       = "Andrés Suárez (Andrachox)"
    Country    = "Colombia"
    Email      = "andracho12@gmail.com"
    License    = "MIT License (Open Source)"
    LegalNote  = "No puede ser usado bajo términos ilegales"
    Version    = "5.0.0-final"
    BuildDate  = Get-Date -Format "yyyy-MM-dd"
    Copyright  = "© 2025 Andrachox. Todos los derechos reservados."
    GitHubRepo = "https://github.com/andracho12/SuiteIT"
}

$script:Config = @{
    AppName                 = "Suite IT Professional"
    Version                 = "5.0"
    LogMaxSizeMB            = 10
    LogMaxFiles             = 5
    BackupBeforeCriticalOps = $true
    MaxRetryAttempts        = 3
}

$script:Paths = @{
    AppData = Join-Path $env:LOCALAPPDATA "SuiteIT-Professional"
    Logs    = Join-Path $env:LOCALAPPDATA "SuiteIT-Professional\Logs"
    Config  = Join-Path $env:LOCALAPPDATA "SuiteIT-Professional\config.json"
    Backup  = Join-Path $env:LOCALAPPDATA "SuiteIT-Professional\Backups"
}

$script:LogFile = $null
$global:IsAdmin = $false

# ============================================
# FUNCIONES DE INICIALIZACIÓN
# ============================================

function Initialize-Application {
    try {
        foreach ($path in $script:Paths.Values) {
            if (-not (Test-Path $path)) {
                New-Item -ItemType Directory -Path $path -Force | Out-Null
            }
        }
        Initialize-Logging
        return $true
    }
    catch {
        Write-Warning "Error inicializando: $($_.Exception.Message)"
        return $false
    }
}

function Initialize-Logging {
    $timestamp = Get-Date -Format "yyyy-MM-dd"
    $script:LogFile = Join-Path $script:Paths.Logs "SuiteIT-$timestamp.log"
    
    $logFiles = Get-ChildItem -Path $script:Paths.Logs -Filter "*.log" -ErrorAction SilentlyContinue
    foreach ($file in $logFiles) {
        if (($file.Length / 1MB) -gt $script:Config.LogMaxSizeMB) {
            $archiveName = "$($file.BaseName)-archived-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
            Move-Item -Path $file.FullName -Destination (Join-Path $script:Paths.Logs $archiveName) -Force -ErrorAction SilentlyContinue
        }
    }
    
    $header = @"
================================================================================
SUITE IT PROFESSIONAL v$($script:Config.Version)
Autor: $($script:AuthorInfo.Name) | País: $($script:AuthorInfo.Country)
Sesión: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Usuario: $env:USERNAME | Equipo: $env:COMPUTERNAME
================================================================================
"@
    Add-Content -Path $script:LogFile -Value $header -ErrorAction SilentlyContinue
}

function Write-EnhancedLog {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $caller = (Get-PSCallStack)[1].Command
    $logEntry = "[$timestamp] [$Level] [$caller] $Message"
    
    if ($script:LogFile) {
        Add-Content -Path $script:LogFile -Value $logEntry -ErrorAction SilentlyContinue
    }
}

# ============================================
# FUNCIONES CORE
# ============================================

function Test-AdminPrivileges {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Show-Login {
    param($RequiredLevel)
    
    $validUsers = @{
        "Soporte"       = "Soporte01"
        "Andrachox"     = "Dante010803@*" 
        "Administrador" = "Dante010803@*" 
        "Admin"         = "Dante010803@*"
    }

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Login Requerido - $RequiredLevel"
    $form.Size = New-Object System.Drawing.Size(400, 250)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.BackColor = $ColorBack
    $form.ForeColor = $ColorText
    
    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text = "Iniciar Sesión"
    $lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $lblTitle.Location = New-Object System.Drawing.Point(20, 20)
    $lblTitle.AutoSize = $true
    $form.Controls.Add($lblTitle)
    
    $lblUser = New-Object System.Windows.Forms.Label
    $lblUser.Text = "Usuario:"
    $lblUser.Location = New-Object System.Drawing.Point(40, 70)
    $lblUser.AutoSize = $true
    $form.Controls.Add($lblUser)
    
    $txtUser = New-Object System.Windows.Forms.TextBox
    $txtUser.Location = New-Object System.Drawing.Point(120, 67)
    $txtUser.Width = 200
    $txtUser.BackColor = $ColorInput
    $txtUser.ForeColor = $ColorText
    $txtUser.BorderStyle = 'FixedSingle'
    $form.Controls.Add($txtUser)
    
    $lblPass = New-Object System.Windows.Forms.Label
    $lblPass.Text = "Contraseña:"
    $lblPass.Location = New-Object System.Drawing.Point(40, 110)
    $lblPass.AutoSize = $true
    $form.Controls.Add($lblPass)
    
    $txtPass = New-Object System.Windows.Forms.TextBox
    $txtPass.Location = New-Object System.Drawing.Point(120, 107)
    $txtPass.Width = 200
    $txtPass.UseSystemPasswordChar = $true
    $txtPass.BackColor = $ColorInput
    $txtPass.ForeColor = $ColorText
    $txtPass.BorderStyle = 'FixedSingle'
    $form.Controls.Add($txtPass)
    
    $btnLogin = New-Object System.Windows.Forms.Button
    $btnLogin.Text = "Ingresar"
    $btnLogin.Location = New-Object System.Drawing.Point(120, 160)
    $btnLogin.Width = 100
    $btnLogin.Height = 30
    $btnLogin.FlatStyle = 'Flat'
    $btnLogin.BackColor = $ColorButton
    $btnLogin.ForeColor = 'White'
    $btnLogin.Cursor = [System.Windows.Forms.Cursors]::Hand
    
    $btnLogin.Add_Click({
            $u = $txtUser.Text
            $p = $txtPass.Text
        
            if ($validUsers.ContainsKey($u) -and $validUsers[$u] -eq $p) {
                if ($RequiredLevel -eq "Administrador" -and $u -eq "Soporte") {
                    [System.Windows.Forms.MessageBox]::Show("La cuenta '$u' no tiene permisos de Administrador.", "Acceso Denegado", 'OK', 'Warning')
                    return
                }
                $form.Tag = $true 
                $form.Close()
            }
            else {
                [System.Windows.Forms.MessageBox]::Show("Usuario o contraseña incorrectos.", "Error de Login", 'OK', 'Error')
                $txtPass.Clear()
            }
        })
    
    $form.AcceptButton = $btnLogin
    $form.Controls.Add($btnLogin)
    
    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancelar"
    $btnCancel.Location = New-Object System.Drawing.Point(230, 160)
    $btnCancel.Width = 90
    $btnCancel.Height = 30
    $btnCancel.FlatStyle = 'Flat'
    $btnCancel.ForeColor = 'White'
    $btnCancel.Cursor = [System.Windows.Forms.Cursors]::Hand
    $btnCancel.Add_Click({ $form.Close() }) 
    $form.Controls.Add($btnCancel)
    
    $form.ShowDialog() | Out-Null
    return $form.Tag
}

function Select-AccessLevel {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Suite IT - Selección de Acceso"
    $form.Size = New-Object System.Drawing.Size(400, 300)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.BackColor = $ColorBack
    $form.ForeColor = $ColorText

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = "Seleccione su nivel de acceso:"
    $lbl.Font = New-Object System.Drawing.Font("Segoe UI", 11)
    $lbl.AutoSize = $true
    $lbl.Location = New-Object System.Drawing.Point(80, 40)
    $form.Controls.Add($lbl)

    $y = 80
    foreach ($lvl in @("Usuario", "Soporte", "Administrador")) {
        $btn = New-Object System.Windows.Forms.Button
        $btn.Text = $lvl
        $btn.Tag = $lvl
        $btn.Location = New-Object System.Drawing.Point(100, $y)
        $btn.Width = 200
        $btn.Height = 40
        $btn.FlatStyle = 'Flat'
        $btn.BackColor = $ColorPanel
        $btn.ForeColor = $ColorText
        $btn.Font = New-Object System.Drawing.Font("Segoe UI", 10)
        $btn.Cursor = [System.Windows.Forms.Cursors]::Hand
        
        $btn.Add_Click({
                $btnSender = $this
                $form.Tag = $btnSender.Tag
                $form.Close()
            })
        
        $form.Controls.Add($btn)
        $y += 50
    }

    $form.ShowDialog() | Out-Null
    return $form.Tag
}

function Restart-AsAdmin {
    param([string]$Level = "Administrador")
    try {
        $scriptPath = $PSCommandPath
        if (-not $scriptPath -or -not (Test-Path $scriptPath)) { return $false }
        
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = "powershell.exe"
        $startInfo.Arguments = "-ExecutionPolicy Bypass -NoProfile -File `"$scriptPath`" -AccessLevel $Level"
        $startInfo.Verb = "runas"
        $startInfo.UseShellExecute = $true
        
        [System.Diagnostics.Process]::Start($startInfo) | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Run-Command {
    param([string]$Command)
    try {
        Write-EnhancedLog "Ejecutando: $Command" "INFO"
        $output = Invoke-Expression $Command 2>&1 | Out-String
        Write-EnhancedLog "Éxito" "SUCCESS"
        return $output.Trim()
    }
    catch {
        Write-EnhancedLog "Error: $($_.Exception.Message)" "ERROR"
        return "[ERROR] $($_.Exception.Message)"
    }
}

function Show-Output {
    param([string]$Title, [string]$Content, [int]$Width = 900, [int]$Height = 600)
    
    $outputForm = New-Object System.Windows.Forms.Form
    $outputForm.Text = $Title
    $outputForm.Size = New-Object System.Drawing.Size($Width, $Height)
    $outputForm.StartPosition = 'CenterScreen'
    $outputForm.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    
    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Multiline = $true
    $textBox.ReadOnly = $true
    $textBox.Dock = 'Fill'
    $textBox.ScrollBars = 'Both'
    $textBox.Font = New-Object System.Drawing.Font('Consolas', 10)
    $textBox.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
    $textBox.ForeColor = [System.Drawing.Color]::FromArgb(220, 220, 220)
    $textBox.Text = $Content
    
    $outputForm.Controls.Add($textBox)
    $outputForm.ShowDialog() | Out-Null
}

function Show-Message {
    param([string]$Text, [string]$Title = "Información", [string]$Type = "Information")
    
    $icon = switch ($Type) {
        "Warning" { [System.Windows.Forms.MessageBoxIcon]::Warning }
        "Error" { [System.Windows.Forms.MessageBoxIcon]::Error }
        "Question" { [System.Windows.Forms.MessageBoxIcon]::Question }
        default { [System.Windows.Forms.MessageBoxIcon]::Information }
    }
    
    [System.Windows.Forms.MessageBox]::Show($Text, $Title, [System.Windows.Forms.MessageBoxButtons]::OK, $icon) | Out-Null
}

function Show-Confirmation {
    param([string]$Text, [string]$Title = "Confirmar")
    $result = [System.Windows.Forms.MessageBox]::Show($Text, $Title, [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
    return ($result -eq [System.Windows.Forms.DialogResult]::Yes)
}

function Test-NetworkConnection {
    param([string]$Target, [int]$Count = 4)
    
    $result = "=== PING A $Target ===`r`n`r`n"
    try {
        $pingResults = Test-Connection -ComputerName $Target -Count $Count -ErrorAction Stop
        
        foreach ($ping in $pingResults) {
            $result += "Respuesta de $($ping.Address): tiempo=$($ping.ResponseTime)ms TTL=$($ping.TimeToLive)`r`n"
        }
        
        $success = ($pingResults | Where-Object { $_.StatusCode -eq 0 }).Count
        $lost = $Count - $success
        $lossPercent = [math]::Round(($lost / $Count) * 100, 1)
        
        $avgTime = if ($success -gt 0) {
            [math]::Round(($pingResults | Where-Object { $_.StatusCode -eq 0 } | Measure-Object -Property ResponseTime -Average).Average, 2)
        }
        else { 0 }
        
        $result += "`r`n=== ESTADÍSTICAS ===`r`n"
        $result += "Enviados: $Count | Recibidos: $success | Perdidos: $lost ($lossPercent%)`r`n"
        if ($avgTime -gt 0) { $result += "Tiempo promedio: $avgTime ms`r`n" }
    }
    catch {
        $result += "[ERROR] $($_.Exception.Message)`r`n"
    }
    
    return $result
}

function Show-AboutDialog {
    $aboutForm = New-Object System.Windows.Forms.Form
    $aboutForm.Text = "Acerca de - $($script:Config.AppName)"
    $aboutForm.Size = New-Object System.Drawing.Size(600, 480)
    $aboutForm.StartPosition = 'CenterScreen'
    $aboutForm.FormBorderStyle = 'FixedDialog'
    $aboutForm.MaximizeBox = $false
    $aboutForm.MinimizeBox = $false
    $aboutForm.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $aboutForm.ForeColor = [System.Drawing.Color]::White
    
    # Header Panel
    $pnlHeader = New-Object System.Windows.Forms.Panel
    $pnlHeader.Dock = "Top"
    $pnlHeader.Height = 100
    $pnlHeader.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
    
    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text = $script:Config.AppName
    $lblTitle.Font = New-Object System.Drawing.Font('Segoe UI', 18, [System.Drawing.FontStyle]::Bold)
    $lblTitle.ForeColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
    $lblTitle.AutoSize = $true
    $lblTitle.Location = New-Object System.Drawing.Point(20, 20)
    $pnlHeader.Controls.Add($lblTitle)
    
    $lblVer = New-Object System.Windows.Forms.Label
    $lblVer.Text = "Versión $($script:AuthorInfo.Version)"
    $lblVer.Font = New-Object System.Drawing.Font('Segoe UI', 10)
    $lblVer.ForeColor = [System.Drawing.Color]::LightGray
    $lblVer.AutoSize = $true
    $lblVer.Location = New-Object System.Drawing.Point(25, 60)
    $pnlHeader.Controls.Add($lblVer)
    
    $aboutForm.Controls.Add($pnlHeader)
    
    # Tabs
    $tabs = New-Object System.Windows.Forms.TabControl
    $tabs.Dock = "Fill"
    
    # Tab Info
    $tabInfo = New-Object System.Windows.Forms.TabPage "Información"
    $tabInfo.Padding = New-Object System.Windows.Forms.Padding(20)
    $tabInfo.BackColor = [System.Drawing.Color]::White
    
    $txtInfo = New-Object System.Windows.Forms.TextBox
    $txtInfo.Multiline = $true
    $txtInfo.ReadOnly = $true
    $txtInfo.Dock = "Fill"
    $txtInfo.BorderStyle = "None"
    $txtInfo.BackColor = [System.Drawing.Color]::White
    $txtInfo.ForeColor = [System.Drawing.Color]::Black 
    $txtInfo.ScrollBars = "Vertical" # [FIX] Add scrollbars to ensure all content is accessible
    $txtInfo.Font = New-Object System.Drawing.Font('Segoe UI', 10)
    $txtInfo.Text = "DESARROLLADOR`r`n" +
    "$($script:AuthorInfo.Name)`r`n" +
    "$($script:AuthorInfo.Country)`r`n`r`n" +
    "SISTEMA`r`n" +
    "Fecha Compilación: $($script:AuthorInfo.BuildDate)`r`n" +
    "PowerShell: $($PSVersionTable.PSVersion)`r`n`r`n" +
    "COPYRIGHT`r`n" +
    "$($script:AuthorInfo.Copyright)"
    
    $tabInfo.Controls.Add($txtInfo)
    
    # Tab Licencia
    $tabLic = New-Object System.Windows.Forms.TabPage "Licencia"
    $tabLic.Padding = New-Object System.Windows.Forms.Padding(20)
    $tabLic.BackColor = [System.Drawing.Color]::White
    
    $txtLic = New-Object System.Windows.Forms.TextBox
    $txtLic.Multiline = $true
    $txtLic.ReadOnly = $true
    $txtLic.Dock = "Fill"
    $txtLic.BorderStyle = "None"
    $txtLic.ScrollBars = "Vertical"
    $txtLic.BackColor = [System.Drawing.Color]::White
    $txtLic.ForeColor = [System.Drawing.Color]::Black
    $txtLic.Font = New-Object System.Drawing.Font('Consolas', 9)
    
    $txtLic.Text = "$($script:AuthorInfo.License)`r`n`r`n" +
    "Este software es de código abierto.`r`n" +
    "$($script:AuthorInfo.LegalNote)`r`n`r`n" +
    "Repositorio Github:`r`n" +
    "$($script:AuthorInfo.GitHubRepo)"
    
    $tabLic.Controls.Add($txtLic)
    
    $tabs.TabPages.Add($tabInfo)
    $tabs.TabPages.Add($tabLic)
    $aboutForm.Controls.Add($tabs)
    
    # Bottom Panel
    $pnlBottom = New-Object System.Windows.Forms.Panel
    $pnlBottom.Dock = "Bottom"
    $pnlBottom.Height = 50
    $pnlBottom.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
    
    $btnClose = New-Object System.Windows.Forms.Button
    $btnClose.Text = "Cerrar"
    $btnClose.Size = New-Object System.Drawing.Size(100, 30)
    $btnClose.Location = New-Object System.Drawing.Point(470, 10)
    $btnClose.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $btnClose.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
    $btnClose.ForeColor = [System.Drawing.Color]::White
    $btnClose.FlatStyle = 'Flat'
    
    $pnlBottom.Controls.Add($btnClose)
    $aboutForm.Controls.Add($pnlBottom)
    
    $aboutForm.AcceptButton = $btnClose
    $aboutForm.ShowDialog() | Out-Null
}

function Add-FunctionButton {
    param(
        [System.Windows.Forms.Control]$Parent,
        [string]$Text,
        [int]$Top,
        [scriptblock]$Action,
        [bool]$RequiresAdmin = $false,
        [string]$Description = "Sin descripción disponible.",
        [string]$Risk = "Bajo",
        [int]$Left = 20,
        [int]$Width = 340,
        [int]$Height = 40
    )
    
    $button = New-Object System.Windows.Forms.Button
    $button.Text = if ($RequiresAdmin) { "[ADMIN] $Text" } else { $Text }
    $button.Width = $Width
    $button.Height = $Height
    $button.Left = $Left
    $button.Top = $Top
    $button.FlatStyle = 'Flat'
    $button.ForeColor = [System.Drawing.Color]::White
    
    if ($RequiresAdmin) {
        $button.BackColor = [System.Drawing.Color]::FromArgb(80, 60, 60)
        $button.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(150, 100, 100)
    }
    else {
        $button.BackColor = [System.Drawing.Color]::FromArgb(58, 58, 58)
        $button.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(100, 100, 100)
    }
    
    $button.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $button.Cursor = [System.Windows.Forms.Cursors]::Hand
    
    # [FIX] Capturar variables explícitamente para el Closure
    $capText = $Text
    $capDesc = $Description
    $capRisk = $Risk
    $capAdm = $RequiresAdmin
    
    # [CRITICAL Fix] Capturar el objeto TextBox real para evitar problemas de scope con $script:
    $infoBox = $script:txtGlobalInfo

    # Eventos de Hover Global
    $button.Add_MouseEnter({
            if ($infoBox) {
                # Usar variables capturadas
                $riskIcon = switch ($capRisk) {
                    "Bajo" { "🟢" }
                    "Medio" { "🟡" }
                    "Alto" { "🔴" }
                    "ALTO" { "🔴" }
                    default { "⚪" }
                }
                $admTxt = if ($capAdm) { "SÍ (Requiere Elevación)" } else { "NO" }
            
                $textBuilder = "$capText`r`n`r`n"
                $textBuilder += "$capDesc`r`n`r`n"
                $textBuilder += "Riesgo: $capRisk $riskIcon`r`n"
                $textBuilder += "Requiere Admin: $admTxt"
            
                $infoBox.Text = $textBuilder
            }
        }.GetNewClosure())
    
    $button.Add_MouseLeave({
            if ($infoBox) {
                $infoBox.Text = "Seleccione una función para ver su descripción y riesgos aquí."
            }
        }.GetNewClosure())

    if ($Action) {
        $button.Add_Click({
                if ($RequiresAdmin -and -not $global:IsAdmin) {
                    Show-Message "Esta operación requiere permisos de Administrador." "Permisos Insuficientes" "Warning"
                    Write-EnhancedLog "Acceso denegado: $Text (sin permisos admin)" "WARNING"
                    return
                }
            
                Write-EnhancedLog "Ejecutando: $Text" "INFO"
                & $Action
            }.GetNewClosure())
    }
    
    $Parent.Controls.Add($button)
}

# ============================================
# FUNCIONES CIBERSEGURIDAD
# ============================================

function Get-NetworkSnapshot {
    $adapters = Get-NetAdapter -Physics | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed
    $ips = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -ne 'Loopback Pseudo-Interface 1' } | Select-Object InterfaceAlias, IPAddress, PrefixLength
    $dns = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | Select-Object InterfaceAlias, ServerAddresses
    $routes = Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' } | Select-Object InterfaceAlias, NextHop

    return [PSCustomObject]@{
        Adapters = $adapters
        IPs      = $ips
        DNS      = $dns
        Gateway  = $routes
    }
}

function Get-LocalSurfaceExposure {
    $ports = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, OwningProcess
    $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike "*$" } # Exclude hidden shares
    
    return [PSCustomObject]@{
        OpenPorts = $ports
        Shares    = $shares
    }
}

function Test-WeakConfigurations {
    $results = @{}
    
    # 1. Firewall
    $fw = Get-NetFirewallProfile | Where-Object { $_.Enabled -eq $false }
    if ($fw) { $results["Firewall"] = "⚠️ Desactivado en: $($fw.Name -join ', ')" } else { $results["Firewall"] = "✅ Activo" }
    
    # 2. Remote Registry
    $rr = Get-Service -Name RemoteRegistry -ErrorAction SilentlyContinue
    if ($rr -and $rr.Status -eq 'Running') { $results["RemoteRegistry"] = "⚠️ Activo (Riesgo)" } else { $results["RemoteRegistry"] = "✅ Inactivo" }
    
    # 3. Execution Policy
    $ep = Get-ExecutionPolicy
    if ($ep -eq 'Unrestricted' -or $ep -eq 'Bypass') { $results["ExecutionPolicy"] = "⚠️ $ep (Permisiva)" } else { $results["ExecutionPolicy"] = "✅ $ep" }
    
    # 4. SMBv1 (Check if protocol is enabled - simplified check)
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($smb1 -and $smb1.State -eq 'Enabled') { $results["SMBv1"] = "⚠️ Habilitado (Obsoleto)" } else { $results["SMBv1"] = "✅ Deshabilitado/No encontrado" }

    return $results
}

function Get-PublicIPInfo {
    try {
        $info = Invoke-RestMethod -Uri "https://ipinfo.io/json" -TimeoutSec 5
        return $info
    }
    catch {
        return $null
    }
}

function New-CyberSecReport {
    $path = Join-Path ([Environment]::GetFolderPath("Desktop")) "CyberSec_Report_$(Get-Date -Format 'yyyyMMdd-HHmm').txt"
    $sb = new-object System.Text.StringBuilder
    
    $sb.AppendLine("=== REPORTE DE CIBERSEGURIDAD PREVENTIVA ===")
    $sb.AppendLine("Fecha: $(Get-Date)")
    $sb.AppendLine("Equipo: $env:COMPUTERNAME")
    $sb.AppendLine("Usuario: $env:USERNAME")
    $sb.AppendLine("-" * 50)
    
    $sb.AppendLine("`r`n[1. SNAPSHOT DE RED]")
    $snap = Get-NetworkSnapshot
    $sb.AppendLine(($snap | Out-String))
    
    $sb.AppendLine("`r`n[2. SUPERFICIE DE EXPOSICIÓN]")
    $surf = Get-LocalSurfaceExposure
    $sb.AppendLine("Puertos en Escucha:")
    $sb.AppendLine(($surf.OpenPorts | Out-String))
    $sb.AppendLine("Carpetas Compartidas:")
    $sb.AppendLine(($surf.Shares | Out-String))
    
    $sb.AppendLine("`r`n[3. CONFIGURACIONES DÉBILES]")
    $weak = Test-WeakConfigurations
    $weak.GetEnumerator() | ForEach-Object { $sb.AppendLine("$($_.Key): $($_.Value)") }
    
    Set-Content -Path $path -Value $sb.ToString()
    return $path
}

# ============================================
# INICIALIZACIÓN
# ============================================

if (-not (Initialize-Application)) {
    [System.Windows.Forms.MessageBox]::Show("No se pudo inicializar la aplicación.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    exit 1
}

$global:IsAdmin = Test-AdminPrivileges
Write-EnhancedLog "Ejecutando como Admin: $global:IsAdmin" "INFO"

# ============================================
# LOGICA DE LOGIN E INICIO
# ============================================

# 1. Si no hay nivel, pedir selección.
if ([string]::IsNullOrEmpty($AccessLevel)) {
    $AccessLevel = Select-AccessLevel
    if (-not $AccessLevel) { exit } 
    
    # 2. Validar credenciales
    switch ($AccessLevel) {
        "Usuario" { }
        "Soporte" {
            if (-not (Show-Login "Soporte")) { exit }
        }
        "Administrador" {
            if (-not (Show-Login "Administrador")) { exit }
            
            # Si Login OK, verificar elevación
            if (-not $global:IsAdmin) {
                if (-not (Restart-AsAdmin "Administrador")) {
                    [System.Windows.Forms.MessageBox]::Show("Se requiere elevación de privilegios para continuar. La aplicación se cerrará.", "Acceso Denegado", 'OK', 'Error')
                }
                exit 
            }
        }
    }
}
else {
    # 3. Validar argumento tras reinicio
    if ($AccessLevel -eq "Administrador" -and -not $global:IsAdmin) {
        if (-not (Restart-AsAdmin "Administrador")) {
            [System.Windows.Forms.MessageBox]::Show("No se pudo obtener privilegios de Administrador. Intente ejecutar manualmente como Admin.", "Error", 'OK', 'Error')
        }
        exit
    }
}

Write-EnhancedLog "Iniciando como nivel: $AccessLevel" "INFO"
# ============================================
# FORMULARIO PRINCIPAL
# ============================================

$mainForm = New-Object System.Windows.Forms.Form
$mainForm.Text = "$($script:Config.AppName) v$($script:Config.Version)"
$mainForm.Size = New-Object System.Drawing.Size(1200, 700)
$mainForm.StartPosition = "CenterScreen"
$mainForm.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)

$iconPath = Join-Path (Split-Path -Parent $PSCommandPath) "Logo.ico"
if (Test-Path $iconPath) {
    $mainForm.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($iconPath)
}
else {
    $mainForm.Icon = $null
}

# ============================================
# CREAR TABS CON NOMBRES ÚNICOS
# ============================================

$tabRed = New-Object System.Windows.Forms.TabPage
$tabRed.Text = "🌐 Red"
$tabRed.Name = "TabRed"

$tabUsuarios = New-Object System.Windows.Forms.TabPage
$tabUsuarios.Text = "👤 Usuarios"
$tabUsuarios.Name = "TabUsuarios"

$tabServicios = New-Object System.Windows.Forms.TabPage
$tabServicios.Text = "⚙️ Servicios"
$tabServicios.Name = "TabServicios"

$tabSeguridad = New-Object System.Windows.Forms.TabPage
$tabSeguridad.Text = "🔒 Seguridad"
$tabSeguridad.Name = "TabSeguridad"

$tabRemoto = New-Object System.Windows.Forms.TabPage
$tabRemoto.Text = "📡 Remoto"
$tabRemoto.Name = "TabRemoto"

$tabMantenimiento = New-Object System.Windows.Forms.TabPage
$tabMantenimiento.Text = "🔧 Mantenimiento"
$tabMantenimiento.Name = "TabMantenimiento"

$tabSistema = New-Object System.Windows.Forms.TabPage
$tabSistema.Text = "💻 Sistema"
$tabSistema.Name = "TabSistema"

$tabCiberseguridad = New-Object System.Windows.Forms.TabPage
$tabCiberseguridad.Text = "🛡️ Ciberseguridad"
$tabCiberseguridad.Name = "TabCiberseguridad"

foreach ($tab in @($tabRed, $tabUsuarios, $tabServicios, $tabSeguridad, $tabRemoto, $tabMantenimiento, $tabSistema, $tabCiberseguridad)) {
    $tab.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
    $tab.AutoScroll = $true
    $tab.Padding = New-Object System.Windows.Forms.Padding(10)
}

# ============================================
# MENÚ UNIFICADO
# ============================================

$menuStrip = New-Object System.Windows.Forms.MenuStrip
$menuStrip.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
$menuStrip.ForeColor = [System.Drawing.Color]::White
$menuStrip.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$mainForm.MainMenuStrip = $menuStrip

# Menú Archivo
$fileMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$fileMenu.Text = "Archivo"
$fileMenu.ForeColor = [System.Drawing.Color]::White

$exitMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$exitMenuItem.Text = "Salir (Ctrl+Q)"
$exitMenuItem.Add_Click({ $mainForm.Close() })
$fileMenu.DropDownItems.Add($exitMenuItem)

# Menú Ver (Módulos)
$viewMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$viewMenu.Text = "Ver"
$viewMenu.ForeColor = [System.Drawing.Color]::White

$menuItemRed = New-Object System.Windows.Forms.ToolStripMenuItem
$menuItemRed.Text = "Red"
$menuItemRed.Add_Click({ $tabControl.SelectedTab = $tabRed })

$menuItemUsuarios = New-Object System.Windows.Forms.ToolStripMenuItem
$menuItemUsuarios.Text = "Usuarios"
$menuItemUsuarios.Add_Click({ $tabControl.SelectedTab = $tabUsuarios })

$menuItemServicios = New-Object System.Windows.Forms.ToolStripMenuItem
$menuItemServicios.Text = "Servicios"
$menuItemServicios.Add_Click({ $tabControl.SelectedTab = $tabServicios })

$menuItemSeguridad = New-Object System.Windows.Forms.ToolStripMenuItem
$menuItemSeguridad.Text = "Seguridad"
$menuItemSeguridad.Add_Click({ $tabControl.SelectedTab = $tabSeguridad })

$menuItemRemoto = New-Object System.Windows.Forms.ToolStripMenuItem
$menuItemRemoto.Text = "Remoto"
$menuItemRemoto.Add_Click({ $tabControl.SelectedTab = $tabRemoto })

$menuItemMantenimiento = New-Object System.Windows.Forms.ToolStripMenuItem
$menuItemMantenimiento.Text = "Mantenimiento"
$menuItemMantenimiento.Add_Click({ $tabControl.SelectedTab = $tabMantenimiento })

$menuItemSistema = New-Object System.Windows.Forms.ToolStripMenuItem
$menuItemSistema.Text = "Sistema"
$menuItemSistema.Add_Click({ $tabControl.SelectedTab = $tabSistema })

$menuItemCiber = New-Object System.Windows.Forms.ToolStripMenuItem
$menuItemCiber.Text = "Ciberseguridad"
$menuItemCiber.Add_Click({ $tabControl.SelectedTab = $tabCiberseguridad })

$viewMenu.DropDownItems.AddRange(@(
        $menuItemRed,
        $menuItemUsuarios,
        $menuItemServicios,
        $menuItemSeguridad,
        $menuItemRemoto,
        $menuItemMantenimiento,
        $menuItemSistema,
        $menuItemCiber
    ))

# Menú Ayuda
$helpMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$helpMenu.Text = "Ayuda"
$helpMenu.ForeColor = [System.Drawing.Color]::White

$aboutMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$aboutMenuItem.Text = "Acerca de..."
$aboutMenuItem.Add_Click({ Show-AboutDialog })

$helpMenu.DropDownItems.Add($aboutMenuItem)

# Agregar menús a la barra
$menuStrip.Items.AddRange(@($fileMenu, $viewMenu, $helpMenu))
$mainForm.Controls.Add($menuStrip)

# Atajos de teclado
$mainForm.KeyPreview = $true
$mainForm.Add_KeyDown({
        if ($_.Control -and $_.KeyCode -eq 'Q') { $mainForm.Close() }
    })


# Panel de Advertencia
if (-not $global:IsAdmin) {
    $warningPanel = New-Object System.Windows.Forms.Panel
    $warningPanel.Dock = 'Top'
    $warningPanel.Height = 60
    $warningPanel.BackColor = [System.Drawing.Color]::FromArgb(255, 193, 7)
    
    $warningLabel = New-Object System.Windows.Forms.Label
    $warningLabel.Text = "⚠ ADVERTENCIA: Sin permisos de administrador. Funciones limitadas."
    $warningLabel.Left = 10
    $warningLabel.Top = 5
    $warningLabel.Width = 800
    $warningLabel.Height = 25
    $warningLabel.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
    $warningLabel.ForeColor = [System.Drawing.Color]::Black
    
    $elevateButton = New-Object System.Windows.Forms.Button
    $elevateButton.Text = "Reiniciar como Administrador"
    $elevateButton.Left = 10
    $elevateButton.Top = 30
    $elevateButton.Width = 220
    $elevateButton.Height = 25
    $elevateButton.BackColor = [System.Drawing.Color]::FromArgb(200, 50, 50)
    $elevateButton.ForeColor = [System.Drawing.Color]::White
    $elevateButton.FlatStyle = 'Flat'
    $elevateButton.Add_Click({ if (Restart-AsAdmin) { $mainForm.Close() } })
    
    $warningPanel.Controls.AddRange(@($warningLabel, $elevateButton))
    $mainForm.Controls.Add($warningPanel)
}

# ============================================
# TAB CONTROL
# ============================================

# ============================================
# LAYOUT GLOBAL (SIDEBAR + TABS)
# ============================================

# 1. Panel Global de Información (Derecha)
$pnlRightGlobal = New-Object System.Windows.Forms.Panel
$pnlRightGlobal.Dock = "Right"
$pnlRightGlobal.Width = 320
$pnlRightGlobal.BackColor = [System.Drawing.Color]::FromArgb(35, 35, 38)
$pnlRightGlobal.Padding = New-Object System.Windows.Forms.Padding(15)

# [LOGO] Branding en el panel derecho (Parte inferior)
$picLogo = New-Object System.Windows.Forms.PictureBox
$picLogo.Dock = "Bottom"
$picLogo.Height = 100
$picLogo.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::Zoom
$picLogo.BackColor = [System.Drawing.Color]::Transparent
$logoPath = Join-Path (Split-Path -Parent $PSCommandPath) "Logo.png"
if (Test-Path $logoPath) {
    $picLogo.Image = [System.Drawing.Image]::FromFile($logoPath)
}
$pnlRightGlobal.Controls.Add($picLogo)

# Título después del logo para que quede arriba en el stack (Bottom dock va pegando hacia arriba)
$lblGlobalTitle = New-Object System.Windows.Forms.Label
$lblGlobalTitle.Text = "ℹ️ Información"
$lblGlobalTitle.Dock = "Top"
$lblGlobalTitle.Height = 40
$lblGlobalTitle.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$lblGlobalTitle.ForeColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$pnlRightGlobal.Controls.Add($lblGlobalTitle)

# Variable de Script para acceso global
$script:txtGlobalInfo = New-Object System.Windows.Forms.TextBox
$script:txtGlobalInfo.Dock = "Fill"
$script:txtGlobalInfo.Multiline = $true
$script:txtGlobalInfo.ReadOnly = $true
$script:txtGlobalInfo.BorderStyle = "None"
$script:txtGlobalInfo.BackColor = [System.Drawing.Color]::FromArgb(35, 35, 38)
$script:txtGlobalInfo.ForeColor = [System.Drawing.Color]::LightGray
$script:txtGlobalInfo.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$script:txtGlobalInfo.Text = "Seleccione una función para ver su descripción y riesgos aquí."
$pnlRightGlobal.Controls.Add($script:txtGlobalInfo)

$mainForm.Controls.Add($pnlRightGlobal)

# 2. Panel Central (Para los Tabs)
$pnlCenter = New-Object System.Windows.Forms.Panel
$pnlCenter.Dock = "Fill"
$mainForm.Controls.Add($pnlCenter)

# Ajuste: Tabs van dentro de pnlCenter ahora
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Dock = 'Fill'
$tabControl.Font = New-Object System.Drawing.Font('Segoe UI', 10)
$tabControl.TabPages.AddRange(@($tabRed, $tabUsuarios, $tabServicios, $tabSeguridad, $tabRemoto, $tabMantenimiento, $tabSistema, $tabCiberseguridad))

$pnlCenter.Controls.Add($tabControl)
$pnlCenter.BringToFront()

# Wire up menu items to tabs
$menuItemRed.Add_Click({ $tabControl.SelectedTab = $tabRed })
$menuItemUsuarios.Add_Click({ $tabControl.SelectedTab = $tabUsuarios })
$menuItemServicios.Add_Click({ $tabControl.SelectedTab = $tabServicios })
$menuItemSeguridad.Add_Click({ $tabControl.SelectedTab = $tabSeguridad })
$menuItemRemoto.Add_Click({ $tabControl.SelectedTab = $tabRemoto })
$menuItemMantenimiento.Add_Click({ $tabControl.SelectedTab = $tabMantenimiento })
$menuItemSistema.Add_Click({ $tabControl.SelectedTab = $tabSistema })

# ============================================
# TAB RED
# ============================================

# ============================================
# TAB RED (MODULAR)
# ============================================

$cmbRedCategories = New-Object System.Windows.Forms.ComboBox
$cmbRedCategories.Dock = "Top"
$cmbRedCategories.DropDownStyle = "DropDownList"
$cmbRedCategories.Font = New-Object System.Drawing.Font("Segoe UI", 11)
$cmbRedCategories.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
$cmbRedCategories.ForeColor = [System.Drawing.Color]::White

$categories = @(
    "1.1.1 🌐 Conectividad y Diagnóstico",
    "1.1.2 🌐 Redes WiFi cercanas",
    "1.1.3 🌐 Redes WiFi guardadas",
    "1.1.4 🌐 Interfaces y Adaptadores",
    "1.1.5 🌐 Configuración IP",
    "1.1.6 🌐 DNS",
    "1.1.7 🌐 Gateway y Rutas",
    "1.1.8 🌐 TCP / UDP",
    "1.1.9 🌐 Firewall",
    "1.1.10 🌐 Puertos y Filtros",
    "1.1.11 🌐 NAT",
    "1.1.12 🌐 IP Helper / Túneles",
    "1.1.13 🌐 Proxy"
)
$cmbRedCategories.Items.AddRange($categories)

$pnlRedTools = New-Object System.Windows.Forms.Panel
$pnlRedTools.Dock = "Fill"
$pnlRedTools.AutoScroll = $true

$tabRed.Controls.Add($pnlRedTools)
$tabRed.Controls.Add($cmbRedCategories)

$cmbRedCategories.Add_SelectedIndexChanged({
        $pnlRedTools.Controls.Clear()
        $cat = $cmbRedCategories.SelectedItem
        $y = 10
    
        switch ($cat) {
            "1.1.1 🌐 Conectividad y Diagnóstico" {
                Add-FunctionButton $pnlRedTools "Test-Connection (Ping)" $y {
                    $t = [Microsoft.VisualBasic.Interaction]::InputBox("Host:", "Ping", "8.8.8.8")
                    if ($t) { Show-Output "Ping $t" (Test-NetworkConnection $t) }
                } $false "Verifica conectividad ICMP básica. Útil para saber si un equipo está online." "Bajo"; $y += 50
            
                Add-FunctionButton $pnlRedTools "Test-NetConnection (Puerto)" $y {
                    $t = [Microsoft.VisualBasic.Interaction]::InputBox("Host (ej: google.com):", "Test-NetConnection", "google.com")
                    $p = [Microsoft.VisualBasic.Interaction]::InputBox("Puerto (Opcional):", "Puerto", "80")
                    if ($t) { 
                        $cmd = "Test-NetConnection -ComputerName $t"
                        if ($p) { $cmd += " -Port $p" }
                        Show-Output "Test-NetConnection" (Run-Command $cmd) 
                    }
                } $false "Prueba conectividad TCP a un puerto específico y realiza traceroute." "Bajo"; $y += 50
            
                Add-FunctionButton $pnlRedTools "Resolve-DnsName" $y {
                    $t = [Microsoft.VisualBasic.Interaction]::InputBox("Nombre:", "DNS", "google.com")
                    if ($t) { Show-Output "DNS Resolve" (Run-Command "Resolve-DnsName -Name $t | Format-List") }
                } $false "Resuelve un nombre de dominio a sus direcciones IP." "Bajo"; $y += 50
            }
        
            "1.1.2 🌐 Redes WiFi cercanas" {
                Add-FunctionButton $pnlRedTools "Escanear Redes (BSSID)" $y {
                    Show-Output "WiFi Scan" (Run-Command "netsh wlan show networks mode=bssid")
                } $false "Lista redes inalámbricas visibles, intensidad y canal." "Medio (Privacidad)"; $y += 50
            }

            "1.1.3 🌐 Redes WiFi guardadas" {
                Add-FunctionButton $pnlRedTools "Ver Perfiles Guardados" $y {
                    Show-Output "WiFi Profiles" (Run-Command "netsh wlan show profiles")
                } $false "Muestra las redes WiFi a las que se ha conectado este equipo." "Bajo"; $y += 50
            }

            "1.1.4 🌐 Interfaces y Adaptadores" {
                Add-FunctionButton $pnlRedTools "Listar Adaptadores" $y {
                    Show-Output "Adaptadores" (Run-Command "Get-NetAdapter | Format-Table -AutoSize")
                } $false "Lista todas las tarjetas de red físicas y virtuales." "Bajo"; $y += 50
            
                Add-FunctionButton $pnlRedTools "Estadísticas Tráfico" $y {
                    Show-Output "Estadísticas" (Run-Command "Get-NetAdapterStatistics | Format-Table -AutoSize")
                } $false "Muestra bytes enviados y recibidos por interfaz." "Bajo"; $y += 50
            
                Add-FunctionButton $pnlRedTools "Info IP Rápida (ipconfig)" $y {
                    Show-Output "IP Config" (Run-Command "ipconfig /all")
                } $false "Resumen rápido de IP, máscara y gateway." "Bajo"; $y += 50
            
                Add-FunctionButton $pnlRedTools "Desactivar Adaptador" $y {
                    $n = [Microsoft.VisualBasic.Interaction]::InputBox("Nombre Adaptador:", "Disable-NetAdapter", "Wi-Fi")
                    if ($n -and (Show-Confirmation "⚠️ RIESGO ALTO: ¿Desactivar '$n'? Perderás conectividad.")) {
                        Run-Command "Disable-NetAdapter -Name '$n' -Confirm:`$false"
                        Show-Message "Comando enviado."
                    }
                } $true "Apaga una tarjeta de red. Provoca desconexión inmediata." "ALTO"; $y += 50
            
                Add-FunctionButton $pnlRedTools "Activar Adaptador" $y {
                    $n = [Microsoft.VisualBasic.Interaction]::InputBox("Nombre Adaptador:", "Enable-NetAdapter", "Wi-Fi")
                    if ($n) { Run-Command "Enable-NetAdapter -Name '$n'"; Show-Message "Comando enviado." }
                } $true "Enciende una tarjeta de red previamente apagada." "Medio"; $y += 50
            }

            "1.1.5 🌐 Configuración IP" {
                Add-FunctionButton $pnlRedTools "Ver IP (Get-NetIPAddress)" $y {
                    Show-Output "IPs" (Run-Command "Get-NetIPAddress | Format-Table InterfaceAlias, IPAddress, PrefixLength -AutoSize")
                } $true "Detalle técnico de direcciones IPv4 e IPv6." "Bajo"; $y += 50
            
                Add-FunctionButton $pnlRedTools "Nueva IP Estática" $y {
                    Show-Message "Funcionalidad avanzada. Use PowerShell directo si no está seguro." "Info"
                } $true "Asigna manualmente una dirección IP. Riesgo de conflicto." "ALTO"; $y += 50
            }

            "1.1.6 🌐 DNS" {
                Add-FunctionButton $pnlRedTools "Ver DNS" $y {
                    Show-Output "DNS Servers" (Run-Command "Get-DnsClientServerAddress | Format-Table InterfaceAlias, ServerAddresses -AutoSize")
                } $false "Muestra los servidores DNS configurados." "Bajo"; $y += 50
            
                Add-FunctionButton $pnlRedTools "Limpiar Caché DNS" $y {
                    Run-Command "Clear-DnsClientCache"
                    Show-Message "Caché DNS limpia."
                } $false "Elimina la caché de resolución de nombres local." "Bajo"; $y += 50
            
                Add-FunctionButton $pnlRedTools "Cambiar DNS" $y {
                    $if = [Microsoft.VisualBasic.Interaction]::InputBox("Interface Alias:", "Set DNS", "Wi-Fi")
                    $dns = [Microsoft.VisualBasic.Interaction]::InputBox("DNS (sep por coma):", "Set DNS", "8.8.8.8,8.8.4.4")
                    if ($if -and $dns -and (Show-Confirmation "¿Cambiar DNS de '$if'?")) {
                        Run-Command "Set-DnsClientServerAddress -InterfaceAlias '$if' -ServerAddresses ($dns).Split(',')"
                    }
                } $true "Asigna servidores DNS manuales (ej. Google, Cloudflare)." "Medio"; $y += 50
            }

            "1.1.7 🌐 Gateway y Rutas" {
                Add-FunctionButton $pnlRedTools "Ver Rutas" $y {
                    Show-Output "Rutas" (Run-Command "Get-NetRoute | Format-Table -AutoSize")
                } $true "Muestra la tabla de enrutamiento del sistema." "Bajo"; $y += 50
            }

            "1.1.8 🌐 TCP / UDP" {
                Add-FunctionButton $pnlRedTools "Conexiones TCP" $y {
                    Show-Output "TCP" (Run-Command "Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | Format-Table -AutoSize")
                } $false "Lista todas las conexiones TCP activas y puertos en escucha." "Bajo"; $y += 50
            
                Add-FunctionButton $pnlRedTools "Endpoints UDP" $y {
                    Show-Output "UDP" (Run-Command "Get-NetUDPEndpoint | Format-Table -AutoSize")
                } $false "Lista puertos UDP abiertos." "Bajo"; $y += 50
            }

            "1.1.9 🌐 Firewall" {
                Add-FunctionButton $pnlRedTools "Ver Reglas" $y {
                    Show-Output "Reglas FW (Primeras 50)" (Run-Command "Get-NetFirewallRule | Select-Object -First 50 | Format-Table")
                } $false "Muestra una muestra de las reglas de Firewall configuradas." "Bajo"; $y += 50
            
                Add-FunctionButton $pnlRedTools "Perfiles FW" $y {
                    Show-Output "Perfiles" (Run-Command "Get-NetFirewallProfile | Format-Table Name, Enabled")
                } $false "Estado (Activo/Inactivo) de perfiles Dominio, Privado y Público." "Bajo"; $y += 50
            }
        
            "1.1.13 🌐 Proxy" {
                Add-FunctionButton $pnlRedTools "Ver Proxy" $y {
                    Show-Output "Proxy" (Run-Command "netsh winhttp show proxy")
                } $false "Muestra la configuración de proxy de sistema (WinHTTP)." "Bajo"; $y += 50
            }
        
            default {
                Add-FunctionButton $pnlRedTools "Opción en desarrollo: $cat" $y {
                    Show-Message "Módulo aún no implementado por completo."
                } $false "Función en construcción." "N/A"
            }
        }
    })


# Seleccionar primera categoría por defecto
$cmbRedCategories.SelectedIndex = 0

Add-FunctionButton $tabRed 'Adaptadores de Red' 260 {
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue
    if ($adapters) {
        $output = "=== ADAPTADORES ===`r`n`r`n"
        foreach ($adapter in $adapters) {
            $output += "Nombre: $($adapter.Name)`r`nEstado: $($adapter.Status)`r`nVelocidad: $($adapter.LinkSpeed)`r`nMAC: $($adapter.MacAddress)`r`n---`r`n"
        }
        Show-Output "Adaptadores" $output
    }
}

Add-FunctionButton $tabRed 'Diagnóstico Completo' 310 {
    Show-Message "Ejecutando diagnóstico..." "Procesando"
    $diag = "=" * 80 + "`r`nDIAGNOSTICO DE RED`r`n" + "=" * 80 + "`r`n`r`n"
    $diag += "=== IP CONFIG ===`r`n" + (Run-Command "ipconfig /all") + "`r`n`r`n"
    $diag += "=== RUTAS ===`r`n" + (Run-Command "route print") + "`r`n`r`n"
    $diag += "=== CONEXIONES ===`r`n" + (Run-Command "netstat -ano") + "`r`n`r`n"
    $diag += "=== TEST ===`r`n" + (Test-NetworkConnection -Target "8.8.8.8" -Count 2)
    Show-Output "Diagnóstico" $diag 1100 700
}

Add-FunctionButton $tabRed 'Resetear TCP/IP' 360 {
    if (Show-Confirmation "¿Resetear TCP/IP completo? Se recomienda reiniciar después.") {
        $result = "=== RESET TCP/IP ===`r`n`r`n"
        $result += "TCP/IP...`r`n" + (Run-Command "netsh int ip reset") + "`r`n`r`n"
        $result += "Winsock...`r`n" + (Run-Command "netsh winsock reset") + "`r`n`r`n"
        $result += "[OK] Se recomienda REINICIAR."
        Show-Output "Reset TCP/IP" $result
        
        if (Show-Confirmation "¿Reiniciar AHORA?") {
            Restart-Computer -Force
        }
    }
} -RequiresAdmin $true

# ============================================
# TAB USUARIOS
# ============================================

Add-FunctionButton $tabUsuarios 'Listar Usuarios' 10 {
    try {
        $users = Get-LocalUser | Select-Object Name, Enabled, LastLogon | Sort-Object Name
        $output = "=== USUARIOS LOCALES ===`r`n`r`n"
        foreach ($user in $users) {
            $enabled = if ($user.Enabled) { 'Si' } else { 'No' }
            $lastLogon = if ($user.LastLogon) { $user.LastLogon.ToString('yyyy-MM-dd HH:mm') } else { 'Nunca' }
            $output += "Usuario: $($user.Name)`r`nHabilitado: $enabled`r`nÚltimo Acceso: $lastLogon`r`n---`r`n"
        }
        Show-Output "Usuarios" $output
    }
    catch {
        Show-Message "Error: $($_.Exception.Message)" "Error" "Error"
    }
}

Add-FunctionButton $tabUsuarios 'Crear Usuario' 60 {
    $username = [Microsoft.VisualBasic.Interaction]::InputBox("Nombre de usuario:", "Crear", "")
    if ([string]::IsNullOrWhiteSpace($username)) { return }
    
    $password = [Microsoft.VisualBasic.Interaction]::InputBox("Contraseña:", "Contraseña", "")
    if ([string]::IsNullOrWhiteSpace($password)) { return }
    
    try {
        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        New-LocalUser -Name $username -Password $securePassword -FullName $username -Description "Creado por Suite IT" -ErrorAction Stop
        Show-Message "Usuario '$username' creado." "Éxito"
    }
    catch {
        Show-Message "Error: $($_.Exception.Message)" "Error" "Error"
    }
} -RequiresAdmin $true

Add-FunctionButton $tabUsuarios 'Deshabilitar/Habilitar' 110 {
    $username = [Microsoft.VisualBasic.Interaction]::InputBox("Usuario:", "Gestión", "")
    if ([string]::IsNullOrWhiteSpace($username)) { return }
    
    try {
        $user = Get-LocalUser -Name $username -ErrorAction Stop
        $action = if ($user.Enabled) { "deshabilitar" } else { "habilitar" }
        
        if (Show-Confirmation "¿$action '$username'?") {
            if ($user.Enabled) {
                Disable-LocalUser -Name $username -ErrorAction Stop
            }
            else {
                Enable-LocalUser -Name $username -ErrorAction Stop
            }
            Show-Message "Usuario '$username' ${action}do." "Éxito"
        }
    }
    catch {
        Show-Message "Error: $($_.Exception.Message)" "Error" "Error"
    }
} -RequiresAdmin $true

Add-FunctionButton $tabUsuarios 'Cambiar Contraseña' 160 {
    $username = [Microsoft.VisualBasic.Interaction]::InputBox("Usuario:", "Contraseña", "")
    if ([string]::IsNullOrWhiteSpace($username)) { return }
    
    $newPassword = [Microsoft.VisualBasic.Interaction]::InputBox("Nueva contraseña:", "Contraseña", "")
    if ([string]::IsNullOrWhiteSpace($newPassword)) { return }
    
    try {
        $securePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force
        Set-LocalUser -Name $username -Password $securePassword -ErrorAction Stop
        Show-Message "Contraseña actualizada." "Éxito"
    }
    catch {
        Show-Message "Error: $($_.Exception.Message)" "Error" "Error"
    }
} -RequiresAdmin $true

Add-FunctionButton $tabUsuarios 'Eliminar Usuario' 210 {
    $username = [Microsoft.VisualBasic.Interaction]::InputBox("ADVERTENCIA: IRREVERSIBLE`n`nUsuario a ELIMINAR:", "Eliminar", "")
    if ([string]::IsNullOrWhiteSpace($username)) { return }
    
    if (Show-Confirmation "¿CONFIRMA eliminar '$username'? NO se puede deshacer.") {
        try {
            Remove-LocalUser -Name $username -ErrorAction Stop
            Show-Message "Usuario eliminado." "Éxito"
        }
        catch {
            Show-Message "Error: $($_.Exception.Message)" "Error" "Error"
        }
    }
} -RequiresAdmin $true

Add-FunctionButton $tabUsuarios 'Agregar a Grupo' 260 {
    $username = [Microsoft.VisualBasic.Interaction]::InputBox("Usuario:", "Grupo", "")
    if ([string]::IsNullOrWhiteSpace($username)) { return }
    
    $groupName = [Microsoft.VisualBasic.Interaction]::InputBox("Grupo (Administrators, Users, etc):", "Grupo", "Users")
    if ([string]::IsNullOrWhiteSpace($groupName)) { return }
    
    try {
        Add-LocalGroupMember -Group $groupName -Member $username -ErrorAction Stop
        Show-Message "Usuario agregado al grupo '$groupName'." "Éxito"
    }
    catch {
        Show-Message "Error: $($_.Exception.Message)" "Error" "Error"
    }
} -RequiresAdmin $true

# ============================================
# TAB SERVICIOS
# ============================================

Add-FunctionButton $tabServicios 'Listar Servicios' 10 {
    try {
        $services = Get-Service | Sort-Object DisplayName
        $output = "=== SERVICIOS ===`r`n`r`n"
        foreach ($service in $services) {
            $status = switch ($service.Status) {
                'Running' { 'Ejecutando' }
                'Stopped' { 'Detenido' }
                default { $service.Status }
            }
            $output += "$($service.DisplayName)`r`nEstado: $status | Tipo: $($service.StartType)`r`n---`r`n"
        }
        $output += "`r`nTotal: $($services.Count) | Activos: $(($services | Where-Object {$_.Status -eq 'Running'}).Count)`r`n"
        Show-Output "Servicios" $output 1000 700
    }
    catch {
        Show-Message "Error: $($_.Exception.Message)" "Error" "Error"
    }
}

Add-FunctionButton $tabServicios 'Iniciar Servicio' 60 {
    $serviceName = [Microsoft.VisualBasic.Interaction]::InputBox("Servicio (ej: Spooler, wuauserv):", "Iniciar", "")
    if ([string]::IsNullOrWhiteSpace($serviceName)) { return }
    
    try {
        $service = Get-Service -Name $serviceName -ErrorAction Stop
        if ($service.Status -eq 'Running') {
            Show-Message "Ya está ejecutándose." "Info"
            return
        }
        if (Show-Confirmation "¿Iniciar '$($service.DisplayName)'?") {
            Start-Service -Name $serviceName -ErrorAction Stop
            Show-Message "Servicio iniciado." "Éxito"
        }
    }
    catch {
        Show-Message "Error: $($_.Exception.Message)" "Error" "Error"
    }
} -RequiresAdmin $true

Add-FunctionButton $tabServicios 'Detener Servicio' 110 {
    $serviceName = [Microsoft.VisualBasic.Interaction]::InputBox("PRECAUCIÓN: Servicio a detener:", "Detener", "")
    if ([string]::IsNullOrWhiteSpace($serviceName)) { return }
    
    try {
        $service = Get-Service -Name $serviceName -ErrorAction Stop
        if ($service.Status -eq 'Stopped') {
            Show-Message "Ya está detenido." "Info"
            return
        }
        if (Show-Confirmation "¿Detener '$($service.DisplayName)'?") {
            Stop-Service -Name $serviceName -Force -ErrorAction Stop
            Show-Message "Servicio detenido." "Éxito"
        }
    }
    catch {
        Show-Message "Error: $($_.Exception.Message)" "Error" "Error"
    }
} -RequiresAdmin $true

Add-FunctionButton $tabServicios 'Reiniciar Servicio' 160 {
    $serviceName = [Microsoft.VisualBasic.Interaction]::InputBox("Servicio:", "Reiniciar", "")
    if ([string]::IsNullOrWhiteSpace($serviceName)) { return }
    
    try {
        $service = Get-Service -Name $serviceName -ErrorAction Stop
        if (Show-Confirmation "¿Reiniciar '$($service.DisplayName)'?") {
            Restart-Service -Name $serviceName -Force -ErrorAction Stop
            Show-Message "Servicio reiniciado." "Éxito"
        }
    }
    catch {
        Show-Message "Error: $($_.Exception.Message)" "Error" "Error"
    }
} -RequiresAdmin $true

Add-FunctionButton $tabServicios 'Detalles de Servicio' 210 {
    $serviceName = [Microsoft.VisualBasic.Interaction]::InputBox("Servicio:", "Detalles", "")
    if ([string]::IsNullOrWhiteSpace($serviceName)) { return }
    
    try {
        $service = Get-Service -Name $serviceName -ErrorAction Stop
        $wmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
        
        $output = "=== DETALLES ===`r`n`r`n"
        $output += "Nombre: $($service.Name)`r`nDisplay: $($service.DisplayName)`r`nEstado: $($service.Status)`r`nInicio: $($service.StartType)`r`n"
        
        if ($wmiService) {
            $output += "`r`n=== ADICIONAL ===`r`n"
            $output += "Descripción: $($wmiService.Description)`r`nRuta: $($wmiService.PathName)`r`nCuenta: $($wmiService.StartName)`r`n"
        }
        
        Show-Output "Detalles - $($service.DisplayName)" $output
    }
    catch {
        Show-Message "Error: $($_.Exception.Message)" "Error" "Error"
    }
}

# ============================================
# TAB SEGURIDAD
# ============================================

Add-FunctionButton $tabSeguridad 'Eventos Seguridad' 10 {
    try {
        $events = Get-EventLog -LogName Security -Newest 50 -ErrorAction Stop
        $output = "=== EVENTOS DE SEGURIDAD ===`r`n`r`n"
        foreach ($evt in $events) {
            $output += "$($evt.TimeGenerated.ToString('yyyy-MM-dd HH:mm:ss')) | $($evt.EntryType)`r`nID: $($evt.EventID)`r`n---`r`n"
        }
        Show-Output "Eventos Seguridad" $output 1100 700
    }
    catch {
        Show-Message "Error. Requiere admin." "Error" "Error"
    }
} -RequiresAdmin $true

Add-FunctionButton $tabSeguridad 'Eventos Sistema' 60 {
    try {
        $events = Get-EventLog -LogName System -Newest 50 -ErrorAction Stop
        $output = "=== EVENTOS SISTEMA ===`r`n`r`n"
        foreach ($evt in $events) {
            $output += "$($evt.TimeGenerated.ToString('yyyy-MM-dd HH:mm:ss')) | $($evt.EntryType)`r`nID: $($evt.EventID)`r`n---`r`n"
        }
        Show-Output "Eventos Sistema" $output 1100 700
    }
    catch {
        Show-Message "Error: $($_.Exception.Message)" "Error" "Error"
    }
}

Add-FunctionButton $tabSeguridad 'Eventos Aplicación' 110 {
    try {
        $events = Get-EventLog -LogName Application -Newest 50 -ErrorAction Stop
        $output = "=== EVENTOS APLICACIÓN ===`r`n`r`n"
        foreach ($evt in $events) {
            $output += "$($evt.TimeGenerated.ToString('yyyy-MM-dd HH:mm:ss')) | $($evt.EntryType)`r`nID: $($evt.EventID)`r`n---`r`n"
        }
        Show-Output "Eventos Aplicación" $output 1100 700
    }
    catch {
        Show-Message "Error: $($_.Exception.Message)" "Error" "Error"
    }
}

Add-FunctionButton $tabSeguridad 'Estado Firewall' 160 {
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        $output = "=== FIREWALL ===`r`n`r`n"
        foreach ($fwProfile in $profiles) {
            $statusIcon = if ($fwProfile.Enabled) { '[ON]' } else { '[OFF]' }
            $output += "Perfil: $($fwProfile.Name) $statusIcon`r`nEntrada: $($fwProfile.DefaultInboundAction)`r`nSalida: $($fwProfile.DefaultOutboundAction)`r`n`r`n"
        }
        Show-Output "Firewall" $output
    }
    catch {
        Show-Message "Error: $($_.Exception.Message)" "Error" "Error"
    }
}

Add-FunctionButton $tabSeguridad 'Reglas Firewall' 210 {
    try {
        $rules = Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.Enabled -eq $true } |
        Select-Object DisplayName, Direction, Action | Sort-Object DisplayName | Select-Object -First 100
        
        $output = "=== REGLAS FIREWALL (100 primeras) ===`r`n`r`n"
        
        foreach ($rule in $rules) {
            $output += "$($rule.DisplayName)`r`nDirección: $($rule.Direction) | Acción: $($rule.Action)`r`n---`r`n"
        }
        
        Show-Output "Reglas Firewall" $output 1100 700
    }
    catch {
        Show-Message "Error: $($_.Exception.Message)" "Error" "Error"
    }
}

# ============================================
# TAB REMOTO
# ============================================

Add-FunctionButton $tabRemoto 'Conectar RDP' 10 {
    $target = [Microsoft.VisualBasic.Interaction]::InputBox("IP o equipo:", "RDP", "")
    if (-not [string]::IsNullOrWhiteSpace($target)) {
        try {
            Start-Process mstsc -ArgumentList "/v:$target" -ErrorAction Stop
        }
        catch {
            Show-Message "Error: $($_.Exception.Message)" "Error" "Error"
        }
    }
}

Add-FunctionButton $tabRemoto 'Reiniciar Remoto' 60 {
    $computer = [Microsoft.VisualBasic.Interaction]::InputBox("Equipo:", "Reiniciar", "")
    if ([string]::IsNullOrWhiteSpace($computer)) { return }
    
    if (Show-Confirmation "¿Confirma reinicio de '$computer'?") {
        try {
            Run-Command "shutdown /r /m \\$computer /t 30 /f /c 'Reinicio por Suite IT'"
            Show-Message "Comando enviado. Reinicio en 30s." "Éxito"
        }
        catch {
            Show-Message "Error: $($_.Exception.Message)" "Error" "Error"
        }
    }
} -RequiresAdmin $true

Add-FunctionButton $tabRemoto 'Apagar Remoto' 110 {
    $computer = [Microsoft.VisualBasic.Interaction]::InputBox("Equipo:", "Apagar", "")
    if ([string]::IsNullOrWhiteSpace($computer)) { return }
    
    if (Show-Confirmation "¿CONFIRMA apagado de '$computer'?") {
        try {
            Run-Command "shutdown /s /m \\$computer /t 30 /f /c 'Apagado por Suite IT'"
            Show-Message "Comando enviado. Apagado en 30s." "Éxito"
        }
        catch {
            Show-Message "Error: $($_.Exception.Message)" "Error" "Error"
        }
    }
} -RequiresAdmin $true

Add-FunctionButton $tabRemoto 'Info Remota' 160 {
    $computer = [Microsoft.VisualBasic.Interaction]::InputBox("Equipo:", "Info", "")
    if ([string]::IsNullOrWhiteSpace($computer)) { return }
    
    try {
        Show-Message "Consultando..." "Procesando"
        
        $output = "=== INFO REMOTA ===`r`n`r`nEquipo: $computer`r`n`r`n"
        
        $cs = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $computer -ErrorAction Stop
        $os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $computer -ErrorAction Stop
        $bios = Get-WmiObject -Class Win32_BIOS -ComputerName $computer -ErrorAction Stop
        
        $output += "=== SISTEMA ===`r`n"
        $output += "OS: $($os.Caption)`r`nVersión: $($os.Version)`r`nArquitectura: $($os.OSArchitecture)`r`n"
        $output += "Boot: $($os.ConvertToDateTime($os.LastBootUpTime).ToString('yyyy-MM-dd HH:mm:ss'))`r`n`r`n"
        
        $output += "=== HARDWARE ===`r`n"
        $output += "Fabricante: $($cs.Manufacturer)`r`nModelo: $($cs.Model)`r`nSerial: $($bios.SerialNumber)`r`n"
        $output += "RAM: $([math]::Round($cs.TotalPhysicalMemory/1GB,2)) GB`r`n`r`n"
        
        $output += "=== USUARIO ===`r`n"
        $output += "Actual: $($cs.UserName)`r`nDominio: $($cs.Domain)`r`n"
        
        Show-Output "Info - $computer" $output
    }
    catch {
        Show-Message "Error: $($_.Exception.Message)`n`nVerifique:`n- Equipo encendido`n- Permisos`n- Firewall WMI" "Error" "Error"
    }
}

# ============================================
# TAB MANTENIMIENTO
# ============================================

Add-FunctionButton $tabMantenimiento 'Limpieza Temporales' 10 {
    if (Show-Confirmation "¿Eliminar temporales?") {
        Show-Message "Limpiando..." "Procesando"
        $output = "=== LIMPIEZA ===`r`n`r`n"
        $totalDeleted = 0
        
        try {
            $items = Get-ChildItem -Path $env:TEMP -Recurse -Force -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                try {
                    Remove-Item $item.FullName -Recurse -Force -ErrorAction Stop
                    $totalDeleted++
                }
                catch {}
            }
        }
        catch {}
        
        $output += "Archivos eliminados: $totalDeleted`r`n"
        Show-Output "Limpieza" $output
    }
}

Add-FunctionButton $tabMantenimiento 'Vaciar Papelera' 60 {
    if (Show-Confirmation "¿Vaciar papelera? NO se puede deshacer.") {
        try {
            Clear-RecycleBin -Force -ErrorAction Stop
            Show-Message "Papelera vaciada." "Éxito"
        }
        catch {
            Show-Message "Error: $($_.Exception.Message)" "Error" "Error"
        }
    }
}

Add-FunctionButton $tabMantenimiento 'CHKDSK' 110 {
    $drive = [Microsoft.VisualBasic.Interaction]::InputBox("Unidad (sin :):", "CHKDSK", "C")
    if (-not [string]::IsNullOrWhiteSpace($drive)) {
        Show-Message "Verificando disco..." "Procesando"
        Show-Output "CHKDSK - $drive`:" (Run-Command "chkdsk $drive`: /scan")
    }
} -RequiresAdmin $true

Add-FunctionButton $tabMantenimiento 'SFC' 160 {
    if (Show-Confirmation "¿Ejecutar SFC? Puede tardar 15-30 minutos.") {
        Show-Message "Ejecutando SFC..." "Procesando"
        Show-Output "SFC" (Run-Command "sfc /scannow") 1000 700
    }
} -RequiresAdmin $true

Add-FunctionButton $tabMantenimiento 'DISM' 210 {
    if (Show-Confirmation "¿Ejecutar DISM? Puede tardar 20-40 min y requiere Internet.") {
        Show-Message "Ejecutando DISM..." "Procesando"
        $output = "=== DISM ===`r`n`r`n"
        $output += (Run-Command "DISM /Online /Cleanup-Image /ScanHealth") + "`r`n`r`n"
        $output += (Run-Command "DISM /Online /Cleanup-Image /RestoreHealth")
        Show-Output "DISM" $output 1100 700
    }
} -RequiresAdmin $true

Add-FunctionButton $tabMantenimiento 'Limpieza Avanzada' 260 {
    if (Show-Confirmation "¿Limpieza avanzada? (Windows Update, minidumps, cache)") {
        try {
            Show-Message "Limpiando..." "Procesando"
            
            $output = "=== LIMPIEZA AVANZADA ===`r`n`r`n"
            
            $output += "Windows Update...`r`n"
            Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
            Remove-Item "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
            Start-Service wuauserv -ErrorAction SilentlyContinue
            $output += "OK`r`n`r`n"
            
            $output += "Minidumps...`r`n"
            Remove-Item "C:\Windows\Minidump\*" -Recurse -Force -ErrorAction SilentlyContinue
            $output += "OK`r`n`r`n"
            
            $output += "Cache...`r`n"
            Remove-Item "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db" -Force -ErrorAction SilentlyContinue
            $output += "OK`r`n`r`n"
            
            $output += "=== COMPLETADO ===`r`n"
            
            Show-Output "Limpieza Avanzada" $output
        }
        catch {
            Show-Message "Error: $($_.Exception.Message)" "Error" "Error"
        }
    }
} -RequiresAdmin $true

# ============================================
# TAB SISTEMA
# ============================================

Add-FunctionButton $tabSistema 'Info Sistema' 10 {
    Show-Message "Recopilando..." "Procesando"
    try {
        $info = Get-ComputerInfo -ErrorAction Stop
        $output = "=== SISTEMA ===`r`n`r`n"
        $output += "Equipo: $($info.CsName)`r`nFabricante: $($info.CsManufacturer)`r`nModelo: $($info.CsModel)`r`n`r`n"
        $output += "OS: $($info.OsName)`r`nVersión: $($info.OsVersion)`r`nArquitectura: $($info.OsArchitecture)`r`n`r`n"
        $output += "CPU: $($info.CsProcessors.Name)`r`nNúcleos: $($info.CsNumberOfProcessors)`r`n`r`n"
        $output += "RAM: $([math]::Round($info.CsTotalPhysicalMemory/1GB,2)) GB`r`n"
        Show-Output "Información Sistema" $output 1000 700
    }
    catch {
        Show-Message "Error: $($_.Exception.Message)" "Error" "Error"
    }
}

Add-FunctionButton $tabSistema 'Ver Procesos' 60 {
    try {
        $processes = Get-Process | Sort-Object CPU -Descending | Select-Object -First 50
        $output = "=== TOP 50 PROCESOS ===`r`n`r`n"
        foreach ($proc in $processes) {
            $memMB = [math]::Round($proc.WorkingSet64 / 1MB, 2)
            $cpu = if ($proc.CPU) { [math]::Round($proc.CPU, 2) } else { 0 }
            $output += "$($proc.ProcessName) | PID: $($proc.Id) | CPU: $cpu s | MEM: $memMB MB`r`n"
        }
        Show-Output "Procesos" $output 1100 700
    }
    catch {
        Show-Message "Error: $($_.Exception.Message)" "Error" "Error"
    }
}

Add-FunctionButton $tabSistema 'Finalizar Proceso' 110 {
    $processName = [Microsoft.VisualBasic.Interaction]::InputBox("Proceso (ej: notepad):", "Finalizar", "")
    if ([string]::IsNullOrWhiteSpace($processName)) { return }
    
    try {
        $processes = Get-Process -Name $processName -ErrorAction Stop
        if (Show-Confirmation "¿Finalizar '$processName' ($($processes.Count) instancia(s))?") {
            Stop-Process -Name $processName -Force -ErrorAction Stop
            Show-Message "Proceso finalizado." "Éxito"
        }
    }
    catch {
        Show-Message "Error: $($_.Exception.Message)" "Error" "Error"
    }
} -RequiresAdmin $true

Add-FunctionButton $tabSistema 'Info Discos' 160 {
    try {
        $disks = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -ne $null }
        $output = "=== DISCOS ===`r`n`r`n"
        foreach ($disk in $disks) {
            $totalGB = [math]::Round(($disk.Used + $disk.Free) / 1GB, 2)
            $freeGB = [math]::Round($disk.Free / 1GB, 2)
            $freePercent = [math]::Round(($disk.Free / ($disk.Used + $disk.Free)) * 100, 1)
            $output += "$($disk.Name)`: | Total: $totalGB GB | Libre: $freeGB GB ($freePercent%)`r`n"
        }
        Show-Output "Discos" $output
    }
    catch {
        Show-Message "Error: $($_.Exception.Message)" "Error" "Error"
    }
}

Add-FunctionButton $tabSistema 'Inventario Hardware' 210 {
    Show-Message "Generando inventario..." "Procesando"
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem
        $bios = Get-CimInstance -ClassName Win32_BIOS
        $proc = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        
        $output = "=== INVENTARIO ===`r`n`r`n"
        $output += "Equipo: $($cs.Name)`r`nSerial: $($bios.SerialNumber)`r`nFabricante: $($cs.Manufacturer)`r`nModelo: $($cs.Model)`r`n`r`n"
        $output += "CPU: $($proc.Name)`r`nNúcleos: $($proc.NumberOfCores)`r`nVelocidad: $($proc.MaxClockSpeed) MHz`r`n`r`n"
        $output += "RAM: $([math]::Round($cs.TotalPhysicalMemory/1GB,2)) GB`r`n`r`n"
        $output += "OS: $($os.Caption)`r`nVersión: $($os.Version)`r`nInstalado: $($os.InstallDate.ToString('yyyy-MM-dd'))`r`n"
        
        Show-Output "Inventario" $output 1000 700
    }
    catch {
        Show-Message "Error: $($_.Exception.Message)" "Error" "Error"
    }
}

Add-FunctionButton $tabSistema 'Ver Log Suite IT' 260 {
    if (Test-Path $script:LogFile) {
        try {
            Show-Output "Log Suite IT" (Get-Content -Path $script:LogFile -Raw) 1000 700
        }
        catch {
            Show-Message "Error al leer log." "Error" "Error"
        }
    }
    else {
        Show-Message "No hay log disponible." "Info"
    }
}

Add-FunctionButton $tabSistema 'Exportar Inventario CSV' 310 {
    try {
        Show-Message "Recopilando datos..." "Procesando"
        
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem
        $bios = Get-CimInstance -ClassName Win32_BIOS
        $proc = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        
        $disks = Get-PhysicalDisk -ErrorAction SilentlyContinue | ForEach-Object {
            "$($_.FriendlyName) - $([math]::Round($_.Size/1GB,2)) GB"
        }
        
        $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
        Where-Object { $_.IPAddress -ne '127.0.0.1' } | 
        Select-Object -ExpandProperty IPAddress
        
        $inventory = [PSCustomObject]@{
            'Equipo'     = $env:COMPUTERNAME
            'Serial'     = $bios.SerialNumber
            'Fabricante' = $cs.Manufacturer
            'Modelo'     = $cs.Model
            'CPU'        = $proc.Name
            'Nucleos'    = $proc.NumberOfCores
            'RAM_GB'     = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
            'Discos'     = ($disks -join "; ")
            'OS'         = $os.Caption
            'Version'    = $os.Version
            'IPs'        = ($ips -join "; ")
            'Fecha'      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            'Usuario'    = $env:USERNAME
        }
        
        $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveDialog.Filter = "CSV (*.csv)|*.csv"
        $saveDialog.FileName = "Inventario-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd').csv"
        
        if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $inventory | Export-Csv -Path $saveDialog.FileName -NoTypeInformation -Encoding UTF8
            
            if (Show-Confirmation "Exportado a:`n`n$($saveDialog.FileName)`n`n¿Abrir?") {
                Start-Process $saveDialog.FileName
            }
        }
    }
    catch {
        Show-Message "Error: $($_.Exception.Message)" "Error" "Error"
    }
}

Add-FunctionButton $tabSistema 'Variables Entorno' 360 {
    try {
        $envVars = Get-ChildItem Env: | Sort-Object Name
        
        $output = "=== VARIABLES DE ENTORNO ===`r`n`r`n"
        
        foreach ($env in $envVars) {
            $output += "$($env.Name)`r`n$($env.Value)`r`n---`r`n"
        }
        
        $output += "`r`nTotal: $($envVars.Count)`r`n"
        
        Show-Output "Variables" $output 1100 700
    }
    catch {
        Show-Message "Error: $($_.Exception.Message)" "Error" "Error"
    }
}

Add-FunctionButton $tabSistema 'Info Red Completa' 410 {
    try {
        $output = "=== RED COMPLETA ===`r`n`r`n"
        
        $adapters = Get-NetAdapter -ErrorAction Stop
        foreach ($adapter in $adapters) {
            $output += "=== $($adapter.Name) ===`r`n"
            $output += "Estado: $($adapter.Status)`r`nMAC: $($adapter.MacAddress)`r`nVelocidad: $($adapter.LinkSpeed)`r`n"
            
            $ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
            foreach ($ip in $ipConfig) {
                if ($ip.AddressFamily -eq 'IPv4') {
                    $output += "IPv4: $($ip.IPAddress)`r`n"
                }
            }
            $output += "`r`n"
        }
        
        Show-Output "Red Completa" $output 1000 700
    }
    catch {
        Show-Message "Error: $($_.Exception.Message)" "Error" "Error"
    }
}

# ============================================
# TAB CIBERSEGURIDAD
# ============================================

$cmbCiberCat = New-Object System.Windows.Forms.ComboBox
$cmbCiberCat.Dock = "Top"
$cmbCiberCat.DropDownStyle = "DropDownList"
$cmbCiberCat.Font = New-Object System.Drawing.Font("Segoe UI", 11)
$cmbCiberCat.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
$cmbCiberCat.ForeColor = [System.Drawing.Color]::White

$ciberCats = @(
    "2.1 Dashboard Ejecutivo",
    "2.2 Reportes Preventivos",
    "2.3 Geolocalización Ética",
    "2.4 Tracking Interno",
    "2.5 Dashboard de Riesgo"
)
$cmbCiberCat.Items.AddRange($ciberCats)

$pnlCiberTools = New-Object System.Windows.Forms.Panel
$pnlCiberTools.Dock = "Fill"
$pnlCiberTools.AutoScroll = $true

$tabCiberseguridad.Controls.Add($pnlCiberTools)
$tabCiberseguridad.Controls.Add($cmbCiberCat)

$cmbCiberCat.Add_SelectedIndexChanged({
        $pnlCiberTools.Controls.Clear()
        $cat = $cmbCiberCat.SelectedItem
        $y = 10
    
        switch ($cat) {
            "2.1 Dashboard Ejecutivo" {
                Add-FunctionButton $pnlCiberTools "Snapshot de Red" $y {
                    Show-Message "Tomando instantánea..." "Procesando"
                    $snap = Get-NetworkSnapshot
                    $out = "=== SNAPSHOT DE RED ===`r`n`r`n"
                    $out += "ADAPTADORES:`r`n" + ($snap.Adapters | Out-String) + "`r`n"
                    $out += "IPs:`r`n" + ($snap.IPs | Out-String) + "`r`n"
                    $out += "DNS:`r`n" + ($snap.DNS | Out-String) + "`r`n"
                    $out += "GATEWAY:`r`n" + ($snap.Gateway | Out-String)
                    Show-Output "Snapshot" $out
                } $true "Captura info de interfaces, IPs y rutas. Solo lectura." "Bajo"; $y += 50
            
                Add-FunctionButton $pnlCiberTools "Auditoría Exposición" $y {
                    Show-Message "Analizando puertos y shares..." "Procesando"
                    $expo = Get-LocalSurfaceExposure
                    $out = "=== SUPERFICIE DE EXPOSICIÓN ===`r`n`r`n"
                    $out += "PUERTOS ABIERTOS (LISTEN):`r`n" + ($expo.OpenPorts | Format-Table -AutoSize | Out-String) + "`r`n"
                    $out += "CARPETAS COMPARTIDAS:`r`n" + ($expo.Shares | Format-Table -AutoSize | Out-String)
                    Show-Output "Exposición" $out
                } $true "Lista puertos en escucha y recursos compartidos." "Info Sensible"; $y += 50
            
                Add-FunctionButton $pnlCiberTools "Estado Firewall" $y {
                    Show-Output "Firewall" (Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction -AutoSize | Out-String)
                } $true "Revisa el estado de los perfiles de firewall." "Bajo"; $y += 50
            
                Add-FunctionButton $pnlCiberTools "Configuraciones Débiles" $y {
                    $weak = Test-WeakConfigurations
                    $out = "=== ANÁLISIS DE HARDENING ===`r`n`r`n"
                    $weak.GetEnumerator() | ForEach-Object { $out += "$($_.Key): $($_.Value)`r`n" }
                    Show-Output "Weak Configs" $out
                } $true "Busca fallos comunes: Firewall off, SMBv1, etc." "Bajo"; $y += 50
            }
        
            "2.2 Reportes Preventivos" {
                Add-FunctionButton $pnlCiberTools "Generar Reporte Completo" $y {
                    Show-Message "Generando reporte. Espere..." "Procesando"
                    try {
                        $path = New-CyberSecReport
                        if (Show-Confirmation "Reporte generado en:`n$path`n¿Abrir ahora?") {
                            Invoke-Item $path
                        }
                    }
                    catch { Show-Message "Error: $_" "Error" "Error" }
                } $true "Genera un TXT consolidado con toda la auditoría." "Bajo"; $y += 50
            }
        
            "2.3 Geolocalización Ética" {
                Add-FunctionButton $pnlCiberTools "Mi Info Pública IP" $y {
                    Show-Message "Consultando ipinfo.io..." "Procesando"
                    $info = Get-PublicIPInfo
                    if ($info) {
                        $out = "=== INFORMACIÓN PÚBLICA ===`r`n`r`n"
                        $out += "IP: $($info.ip)`r`n"
                        $out += "Ciudad: $($info.city)`r`n"
                        $out += "Región: $($info.region)`r`n"
                        $out += "País: $($info.country)`r`n"
                        $out += "Org: $($info.org)`r`n"
                        $out += "Loc: $($info.loc)`r`n"
                        Show-Output "Geo IP" $out
                    }
                    else { Show-Message "No se pudo conectar a ipinfo.io" "Error" "Error" }
                } $true "Consulta API externa para ver datos de la IP pública actual." "Bajo (Salida a Internet)"; $y += 50
            }
        
            "2.4 Tracking Interno" {
                Add-FunctionButton $pnlCiberTools "Ver Cambios Recientes (EventLog)" $y {
                    Show-Message "Buscando eventos de red..." "Procesando"
                    $out = "=== EVENTOS DE RED (Últimos 20) ===`r`n`r`n"
                    $events = Get-WinEvent -LogName "System" -MaxEvents 20 -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -like "*Network*" -or $_.ProviderName -like "*Tcpip*" }
                    if ($events) { $out += ($events | Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-Table -AutoSize | Out-String) }
                    else { $out += "No se encontraron eventos recientes o falta acceso." }
                    Show-Output "Tracking" $out
                } $true "Busca logs del sistema relacionados con redes." "Bajo"; $y += 50
            }
        
            "2.5 Dashboard de Riesgo" {
                Add-FunctionButton $pnlCiberTools "Ver Dashboard de Riesgo" $y {
                    $weak = Test-WeakConfigurations
                    $riskScore = 0
                    $details = ""
                 
                    foreach ($k in $weak.Keys) {
                        if ($weak[$k] -match "⚠️") { 
                            $riskScore++ 
                            $details += "$($k): $($weak[$k])`r`n"
                        }
                    }
                 
                    $status = if ($riskScore -eq 0) { "VERDE - Seguro" } elseif ($riskScore -lt 3) { "AMARILLO - Precaución" } else { "ROJO - PELIGRO" }
                 
                    $msg = "ESTADO DE RIESGO: $status`r`n`r`nHallazgos Críticos ($riskScore):`r`n$details"
                    Show-Output "Risk Dashboard" $msg
                } $true "Calcula un puntaje de riesgo basado en las configuraciones débiles." "Bajo"; $y += 50
            }
        }
    })

$cmbCiberCat.SelectedIndex = 0

# ============================================
# BARRA DE ESTADO
# ============================================

$statusBar = New-Object System.Windows.Forms.StatusStrip
$statusBar.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)

$statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$statusLabel.Text = "$($script:Config.AppName) v$($script:Config.Version) | Usuario: $env:USERNAME | Equipo: $env:COMPUTERNAME"
$statusLabel.ForeColor = [System.Drawing.Color]::White

$adminStatusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
if ($global:IsAdmin) {
    $adminStatusLabel.Text = "Administrador"
    $adminStatusLabel.ForeColor = [System.Drawing.Color]::LightGreen
}
else {
    $adminStatusLabel.Text = "Usuario Estándar"
    $adminStatusLabel.ForeColor = [System.Drawing.Color]::Orange
}

$statusBar.Items.AddRange(@($statusLabel, $adminStatusLabel))
$mainForm.Controls.Add($statusBar)

# ============================================
# MOSTRAR FORMULARIO
# ============================================

Write-EnhancedLog "Mostrando interfaz..." "INFO"

try {
    [void]$mainForm.ShowDialog()
}
catch {
    Write-EnhancedLog "Error interfaz: $($_.Exception.Message)" "ERROR"
}
finally {
    Write-EnhancedLog "===========================================" "INFO"
    Write-EnhancedLog "Suite IT cerrada" "INFO"
    Write-EnhancedLog "Sesión finalizada: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "INFO"
    Write-EnhancedLog "===========================================" "INFO"
}
