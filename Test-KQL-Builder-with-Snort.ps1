<#
.SYNOPSIS
    KQL Query Builder & Snort Converter - Dark Mode Incident Response Edition

.DESCRIPTION
    Tab 1: Interactive KQL builder with persistent DB/JSON storage, advanced dynamic 
    filtering, and maximum SecurityEvent schema coverage.
    
    Tab 2: Snort-to-KQL L7 Web traffic converter.

    UI Aesthetic: GitHub/Dark Mode inspired (#0d1117 background, #161b22 surface, 
    #58a6ff blue accents, #f85149 critical accents, monospace fonts).
#>

[CmdletBinding()]
param([switch]$ResetDb)
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class DarkModeTheme {
    [DllImport("dwmapi.dll")]
    public static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);
    
    [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
    public static extern int SetWindowTheme(IntPtr hWnd, string pszSubAppName, string pszSubIdList);
}
"@

# ================================================================
# COLOR PALETTE & THEMING (Based on provided aesthetic)
# ================================================================
$c_bg       = [System.Drawing.ColorTranslator]::FromHtml("#0d1117")
$c_surface  = [System.Drawing.ColorTranslator]::FromHtml("#161b22")
$c_elevated = [System.Drawing.ColorTranslator]::FromHtml("#21262d")
$c_border   = [System.Drawing.ColorTranslator]::FromHtml("#30363d")
$c_textMain = [System.Drawing.ColorTranslator]::FromHtml("#e6edf3")
$c_textMuted= [System.Drawing.ColorTranslator]::FromHtml("#8b949e")
$c_blue     = [System.Drawing.ColorTranslator]::FromHtml("#58a6ff")
$c_red      = [System.Drawing.ColorTranslator]::FromHtml("#f85149")
$c_green    = [System.Drawing.ColorTranslator]::FromHtml("#3fb950")

$fontUI   = New-Object System.Drawing.Font('Segoe UI', 9)
$fontMono = New-Object System.Drawing.Font('Consolas', 10)

function Apply-Theme($control) {
    $control.BackColor = $c_surface
    $control.ForeColor = $c_textMain
    $control.Font = $fontUI

    if ($control -is [System.Windows.Forms.TextBox] -or $control -is [System.Windows.Forms.ComboBox]) {
        $control.BackColor = $c_bg
        $control.ForeColor = $c_textMain
        
        if ($control -is [System.Windows.Forms.ComboBox]) {
            $control.FlatStyle = 'Flat'
            # Force custom drawing for the dropdown menu items
            $control.DrawMode = [System.Windows.Forms.DrawMode]::OwnerDrawFixed
            $control.Add_DrawItem({
                param($sender, $e)
                if ($e.Index -lt 0) { return }
                $g = $e.Graphics
                $bgBrush = if ($e.State -band [System.Windows.Forms.DrawItemState]::Selected) { New-Object System.Drawing.SolidBrush($c_elevated) } else { New-Object System.Drawing.SolidBrush($c_bg) }
                $textBrush = New-Object System.Drawing.SolidBrush($c_textMain)
                $g.FillRectangle($bgBrush, $e.Bounds)
                $g.DrawString($sender.Items[$e.Index].ToString(), $fontUI, $textBrush, $e.Bounds.X + 2, $e.Bounds.Y + 2)
            })
        }
        # Apply dark mode to scrollbars
        [DarkModeTheme]::SetWindowTheme($control.Handle, "DarkMode_Explorer", $null) | Out-Null
    }
    elseif ($control -is [System.Windows.Forms.NumericUpDown]) {
        # Safe block for NumericUpDown - applies colors but skips the native theme hook that causes crashes
        $control.BackColor = $c_bg
        $control.ForeColor = $c_textMain
    }
    elseif ($control -is [System.Windows.Forms.Button]) {
        $control.FlatStyle = 'Flat'
        $control.FlatAppearance.BorderColor = $c_border
        $control.FlatAppearance.BorderSize = 1
        $control.BackColor = $c_elevated
        $control.ForeColor = $c_blue
        $control.Cursor = [System.Windows.Forms.Cursors]::Hand
    }
    elseif ($control -is [System.Windows.Forms.CheckedListBox]) {
        $control.BackColor = $c_bg
        $control.ForeColor = $c_textMain
        $control.BorderStyle = 'FixedSingle'
    }
    elseif ($control -is [System.Windows.Forms.Panel] -or $control -is [System.Windows.Forms.TabPage]) {
        [DarkModeTheme]::SetWindowTheme($control.Handle, "DarkMode_Explorer", $null) | Out-Null
    }
    
    # Recursively theme children
    foreach ($child in $control.Controls) { Apply-Theme $child }
}

# ================================================================
# PATHS & STORAGE INIT
# ================================================================
$script:DataDir   = Join-Path $env:USERPROFILE 'SecIntel'
$script:AccdbPath = Join-Path $script:DataDir 'KqlBuilder.accdb'
$script:JsonPath  = Join-Path $script:DataDir 'KqlBuilder.json'

if (-not (Test-Path $script:DataDir)) { New-Item -ItemType Directory -Path $script:DataDir -Force | Out-Null }
if ($ResetDb) { Remove-Item $script:AccdbPath, $script:JsonPath -Force -ErrorAction SilentlyContinue }

$script:StorageMode = 'json'; $script:OleDbConnStr = $null

function Initialize-Storage {
    if (-not (Test-Path $script:AccdbPath)) {
        try {
            $catalog = New-Object -ComObject ADOX.Catalog
            $catalog.Create("Provider=Microsoft.ACE.OLEDB.12.0;Data Source=$script:AccdbPath;")
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($catalog) | Out-Null
        } catch { $script:StorageMode = 'json'; if (-not (Test-Path $script:JsonPath)) { '[]' | Set-Content $script:JsonPath -Encoding UTF8 }; return }
    }
    try {
        $script:OleDbConnStr = "Provider=Microsoft.ACE.OLEDB.12.0;Data Source=$script:AccdbPath;Persist Security Info=False;"
        $conn = New-Object System.Data.OleDb.OleDbConnection $script:OleDbConnStr; $conn.Open()
        $schema = $conn.GetSchema('Tables'); $tableExists = $false
        foreach ($row in $schema.Rows) { if ($row['TABLE_NAME'] -eq 'SavedQueries') { $tableExists = $true; break } }
        if (-not $tableExists) {
            $cmd = $conn.CreateCommand()
            $cmd.CommandText = "CREATE TABLE SavedQueries (Id COUNTER PRIMARY KEY, QueryName TEXT(255), Description LONGTEXT, Tags TEXT(500), TableName TEXT(100), KqlText LONGTEXT, CreatedDate DATETIME, LastModified DATETIME)"
            [void]$cmd.ExecuteNonQuery()
        }
        $conn.Close(); $script:StorageMode = 'access'
    } catch { $script:StorageMode = 'json'; if (-not (Test-Path $script:JsonPath)) { '[]' | Set-Content $script:JsonPath -Encoding UTF8 } }
}
Initialize-Storage

function Save-Query {
    param([string]$Name, [string]$Description, [string]$Tags, [string]$TableName, [string]$KqlText)
    $now = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    if ($script:StorageMode -eq 'access') {
        $conn = New-Object System.Data.OleDb.OleDbConnection $script:OleDbConnStr; $conn.Open()
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = "INSERT INTO SavedQueries (QueryName, Description, Tags, TableName, KqlText, CreatedDate, LastModified) VALUES (?, ?, ?, ?, ?, ?, ?)"
        [void]$cmd.Parameters.AddWithValue('@p1', $Name); [void]$cmd.Parameters.AddWithValue('@p2', $Description); [void]$cmd.Parameters.AddWithValue('@p3', $Tags)
        [void]$cmd.Parameters.AddWithValue('@p4', $TableName); [void]$cmd.Parameters.AddWithValue('@p5', $KqlText); [void]$cmd.Parameters.AddWithValue('@p6', $now); [void]$cmd.Parameters.AddWithValue('@p7', $now)
        [void]$cmd.ExecuteNonQuery(); $conn.Close()
    } else {
        $existing = @(Get-Content $script:JsonPath -Raw | ConvertFrom-Json)
        $newId = if ($existing.Count -gt 0) { ($existing | Measure-Object Id -Maximum).Maximum + 1 } else { 1 }
        $entry = [PSCustomObject]@{ Id=$newId; QueryName=$Name; Description=$Description; Tags=$Tags; TableName=$TableName; KqlText=$KqlText; CreatedDate=$now; LastModified=$now }
        $list = @($existing) + $entry; $list | ConvertTo-Json -Depth 5 | Set-Content $script:JsonPath -Encoding UTF8
    }
}

# ================================================================
# SCHEMA & TABLE DEFINITIONS (Maximized for coverage)
# ================================================================
$script:TableDefinitions = @{
    'SecurityEvent' = @{
        ComputerField = 'Computer'; UserField = 'Account'; TimeField = 'TimeGenerated'
        DefaultColumns = @('TimeGenerated','Computer','Account','EventID','Activity','LogonType','IpAddress','ProcessName','CommandLine')
        AvailableColumns = @('TenantId','TimeGenerated','SourceSystem','Account','AccountType','Computer','EventSourceName','Channel','Task','Level','EventData','EventID','Activity','PartitionKey','RowKey','StorageAccount','AzureDeploymentID','AzureTableName','AccessList','AccessMask','AccessReason','AccountDomain','AccountExpires','AccountName','AccountSessionIdentifier','AdditionalInfo','AdditionalInfo2','AllowedToDelegateTo','Attributes','AuditPolicyChanges','AuditsDiscarded','AuthenticationLevel','AuthenticationPackageName','AuthenticationProvider','AuthenticationServer','AuthenticationService','AuthenticationType','CACertificateHash','CalledStationID','CallerProcessId','CallerProcessName','CallingStationID','CAPublicKeyHash','CategoryId','CertificateDatabaseHash','ClassId','ClassName','ClientAddress','ClientIPAddress','ClientName','CommandLine','CompatibleIds','DCDNSName','DeviceDescription','DeviceId','DisplayName','Disposition','DomainBehaviorVersion','DomainName','DomainPolicyChanged','DomainSid','EAPType','ElevatedToken','ErrorCode','ExtendedQuarantineState','FailureReason','FileHash','FilePath','FilePathNoUser','Filter','ForceLogoff','Fqbn','FullyQualifiedSubjectMachineName','FullyQualifiedSubjectUserName','GroupMembership','HandleId','HardwareIds','HomeDirectory','HomePath','ImpersonationLevel','InterfaceUuid','IpAddress','IpPort','KeyLength','LmPackageName','LocationInformation','LockoutDuration','LockoutObservationWindow','LockoutThreshold','LoggingResult','LogonGuid','LogonHours','LogonID','LogonProcessName','LogonType','LogonTypeName','MachineAccountQuota','MachineInventory','MachineLogon','MandatoryLabel','MaxPasswordAge','MemberName','MemberSid','MinPasswordAge','MinPasswordLength','MixedDomainMode','NASIdentifier','NASIPv4Address','NASIPv6Address','NASPort','NASPortType','NetworkPolicyName','NewDate','NewMaxUsers','NewProcessId','NewProcessName','NewRemark','NewShareFlags','NewTime','NewUacValue','NewValue','NewValueType','ObjectName','ObjectServer','ObjectType','ObjectValueName','OemInformation','OldMaxUsers','OldRemark','OldShareFlags','OldUacValue','OldValue','OldValueType','OperationType','PackageName','ParentProcessName','PasswordHistoryLength','PasswordLastSet','PasswordProperties','PreviousDate','PreviousTime','PrimaryGroupId','PrivateKeyUsageCount','PrivilegeList','Process','ProcessId','ProcessName','Properties','ProfilePath','ProtocolSequence','ProxyPolicyName','QuarantineHelpURL','QuarantineSessionID','QuarantineSessionIdentifier','QuarantineState','QuarantineSystemHealthResult','RelativeTargetName','RemoteIpAddress','RemotePort','Requester','RequestId','RestrictedAdminMode','RowsDeleted','SamAccountName','ScriptPath','SecurityDescriptor','ServiceAccount','ServiceFileName','ServiceName','ServiceStartType','ServiceType','SessionName','ShareLocalPath','ShareName','SidHistory','Status','SubjectAccount','SubcategoryGuid','SubcategoryId','Subject','SubjectDomainName','SubjectKeyIdentifier','SubjectLogonId','SubjectMachineName','SubjectMachineSID','SubjectUserName','SubjectUserSid','SubStatus','TableId','TargetAccount','TargetDomainName','TargetInfo','TargetLinkedLogonId','TargetLogonGuid','TargetLogonId','TargetOutboundDomainName','TargetOutboundUserName','TargetServerName','TargetSid','TargetUser','TargetUserName','TargetUserSid','TemplateContent','TemplateDSObjectFQDN','TemplateInternalName','TemplateOID','TemplateSchemaVersion','TemplateVersion','TokenElevationType','TransmittedServices','UserAccountControl','UserParameters','UserPrincipalName','UserWorkstations','VirtualAccount','VendorIds','Workstation','WorkstationName','EventLevelName','SourceComputerId','EventOriginId','MG','TimeCollected','ManagementGroupName','SystemUserId','Version','Opcode','Keywords','Correlation','SystemProcessId','SystemThreadId','EventRecordId','Type','_ResourceId')
        Specifics = @{ EventID = @('','4624','4625','4634','4648','4672','4688','4697','4698','4720','4732','4738','7045','1102'); LogonType = @('','2','3','4','5','7','8','9','10','11') }
        AutoParse = $false; SummarizeBy = @('Account','EventID','Computer')
    }
    'DeviceProcessEvents' = @{
        ComputerField = 'DeviceName'; UserField = 'AccountName'; TimeField = 'TimeGenerated'
        DefaultColumns = @('TimeGenerated','DeviceName','AccountName','FileName','FolderPath','ProcessCommandLine','InitiatingProcessFileName','SHA256')
        AvailableColumns = @('TimeGenerated','DeviceName','AccountName','AccountDomain','FileName','FolderPath','ProcessCommandLine','ProcessId','SHA256','MD5','InitiatingProcessFileName','InitiatingProcessFolderPath','InitiatingProcessCommandLine','InitiatingProcessParentFileName','InitiatingProcessAccountName')
        Specifics = @{}; AutoParse = $false; SummarizeBy = @('FileName','DeviceName','AccountName')
    }
    'DeviceNetworkEvents' = @{
        ComputerField = 'DeviceName'; UserField = 'InitiatingProcessAccountName'; TimeField = 'TimeGenerated'
        DefaultColumns = @('TimeGenerated','DeviceName','RemoteIP','RemotePort','RemoteUrl','InitiatingProcessFileName','InitiatingProcessAccountName','ActionType')
        AvailableColumns = @('TimeGenerated','DeviceName','ActionType','RemoteIP','RemotePort','RemoteUrl','LocalIP','LocalPort','Protocol','InitiatingProcessFileName','InitiatingProcessFolderPath','InitiatingProcessCommandLine','InitiatingProcessAccountName','InitiatingProcessSHA256')
        Specifics = @{ ActionType = @('','ConnectionSuccess','ConnectionFailed','ConnectionAttempt','InboundConnectionAccepted'); Protocol = @('','Tcp','Udp','Icmp') }
        AutoParse = $false; SummarizeBy = @('RemoteIP','InitiatingProcessFileName','DeviceName')
    }
    'CommonSecurityLog' = @{
        ComputerField = 'Computer'; UserField = 'SourceUserName'; TimeField = 'TimeGenerated'
        DefaultColumns = @('TimeGenerated','DeviceVendor','DeviceProduct','Activity','SourceIP','DestinationIP','SourceUserName','Message')
        AvailableColumns = @('TimeGenerated','DeviceVendor','DeviceProduct','DeviceAction','Activity','SourceIP','SourcePort','DestinationIP','DestinationPort','Protocol','SourceUserName','DestinationUserName','RequestURL','Message')
        Specifics = @{}; AutoParse = $false; SummarizeBy = @('DeviceProduct','SourceIP','DestinationIP')
    }
}

# ================================================================
# QUERY BUILDER ENGINE (With Advanced Filters)
# ================================================================
function Build-KqlQuery {
    param($State)
    $tableName = $State.TableName; $tableDef = $script:TableDefinitions[$tableName]
    $sb = New-Object System.Text.StringBuilder
    
    [void]$sb.AppendLine("// ================================================================")
    [void]$sb.AppendLine("// Name: $($State.Name)")
    if ($State.Tags) { [void]$sb.AppendLine("// Tags: $($State.Tags)") }
    [void]$sb.AppendLine("// Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')")
    [void]$sb.AppendLine("// ================================================================")
    [void]$sb.AppendLine($tableName)

    # Standard Filters
    if ($State.TimeRange -ne 'all') { [void]$sb.AppendLine("| where $($tableDef.TimeField) > ago($($State.TimeRange))") }
    if ($State.Computer) { [void]$sb.AppendLine("| where $($tableDef.ComputerField) =~ `"$($State.Computer)`"") }
    if ($State.User) { [void]$sb.AppendLine("| where $($tableDef.UserField) has `"$($State.User)`"") }

    foreach ($k in $State.Specifics.Keys) {
        $v = $State.Specifics[$k]
        if ($v) { if ($k -eq 'EventID' -or $k -eq 'LogonType') { [void]$sb.AppendLine("| where $k == $v") } else { [void]$sb.AppendLine("| where $k =~ `"$v`"") } }
    }

    # Advanced Dynamic Filtering
    if ($State.F_IP) {
        $ipCols = @('IpAddress','RemoteIP','LocalIP','SourceIP','DestinationIP','ClientIPAddress','RemoteIpAddress') | Where-Object { $_ -in $tableDef.AvailableColumns }
        if ($ipCols.Count -gt 0) {
            $conds = $ipCols | ForEach-Object { "$_ has `"$($State.F_IP)`"" }
            [void]$sb.AppendLine("| where " + ($conds -join " or "))
        } else { [void]$sb.AppendLine("// Note: No known IP columns in this schema for filter: $($State.F_IP)") }
    }
    
    if ($State.F_Process) {
        $pCols = @('ProcessName','FileName','InitiatingProcessFileName','ParentProcessName','NewProcessName','FolderPath') | Where-Object { $_ -in $tableDef.AvailableColumns }
        if ($pCols.Count -gt 0) {
            $conds = $pCols | ForEach-Object { "$_ contains `"$($State.F_Process)`"" }
            [void]$sb.AppendLine("| where " + ($conds -join " or "))
        }
    }

    if ($State.F_Cmd) {
        $cCols = @('CommandLine','ProcessCommandLine','InitiatingProcessCommandLine') | Where-Object { $_ -in $tableDef.AvailableColumns }
        if ($cCols.Count -gt 0) {
            $conds = $cCols | ForEach-Object { "$_ contains `"$($State.F_Cmd)`"" }
            [void]$sb.AppendLine("| where " + ($conds -join " or "))
        }
    }

    if ($State.F_Hash) {
        $hCols = @('SHA256','MD5','FileHash') | Where-Object { $_ -in $tableDef.AvailableColumns }
        if ($hCols.Count -gt 0) {
            $conds = $hCols | ForEach-Object { "$_ =~ `"$($State.F_Hash)`"" }
            [void]$sb.AppendLine("| where " + ($conds -join " or "))
        }
    }

    if ($State.AutoParse) {
        [void]$sb.AppendLine("| extend xml = parse_xml(EventData)")
        [void]$sb.AppendLine("| mv-apply d = xml.DataItem.EventData.Data on ( summarize Bag = make_bag(bag_pack(tostring(d['@Name']), tostring(d['#text']))) ) | evaluate bag_unpack(Bag, 'evt_')")
    }

    if ($State.OutputMode -eq 'Summarized' -and $tableDef.SummarizeBy.Count -gt 0) {
        $by = $tableDef.SummarizeBy -join ', '
        [void]$sb.AppendLine("| summarize EventCount=count(), First=min($($tableDef.TimeField)), Last=max($($tableDef.TimeField)) by $by | order by EventCount desc")
    } elseif ($State.Columns.Count -gt 0) {
        [void]$sb.AppendLine("| project " + ($State.Columns -join ', ') + " | order by $($tableDef.TimeField) desc")
    }

    if ($State.Limit -gt 0) { [void]$sb.AppendLine("| take $($State.Limit)") }
    return $sb.ToString()
}

# ================================================================
# GUI CONSTRUCTION (Custom Dark Drawn)
# ================================================================
$form = New-Object System.Windows.Forms.Form
$form.Text = "KQL Builder & L7 Snort Converter"
$form.Size = New-Object System.Drawing.Size(1300, 950)
$form.StartPosition = 'CenterScreen'
$form.BackColor = $c_bg

$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Dock = 'Fill'
$tabControl.DrawMode = [System.Windows.Forms.TabDrawMode]::OwnerDrawFixed
$tabControl.ItemSize = New-Object System.Drawing.Size(180, 30)
$tabControl.SizeMode = 'Fixed'
$tabControl.Add_DrawItem({
    param($sender, $e)
    $g = $e.Graphics; $brush = New-Object System.Drawing.SolidBrush($c_surface)
    $g.FillRectangle($brush, $e.Bounds)
    $textBrush = if ($e.State -eq [System.Windows.Forms.DrawItemState]::Selected) { New-Object System.Drawing.SolidBrush($c_blue) } else { New-Object System.Drawing.SolidBrush($c_textMuted) }
    $g.DrawString($sender.TabPages[$e.Index].Text, $fontUI, $textBrush, $e.Bounds.X + 15, $e.Bounds.Y + 8)
    if ($e.State -eq [System.Windows.Forms.DrawItemState]::Selected) {
        $pen = New-Object System.Drawing.Pen($c_blue, 3)
        $g.DrawLine($pen, $e.Bounds.X, $e.Bounds.Bottom - 1, $e.Bounds.Right, $e.Bounds.Bottom - 1)
    }
})
$form.Controls.Add($tabControl)

$tabBuilder = New-Object System.Windows.Forms.TabPage; $tabBuilder.Text = "Query Builder"
$tabSnort   = New-Object System.Windows.Forms.TabPage; $tabSnort.Text = "Snort to KQL"
$tabControl.TabPages.Add($tabBuilder); $tabControl.TabPages.Add($tabSnort)

# --- TAB 1 (Builder Layout) ---
$split = New-Object System.Windows.Forms.SplitContainer; $split.Dock = 'Fill'; $split.Orientation = 'Vertical'; $split.SplitterDistance = 600
$tabBuilder.Controls.Add($split)

$inputPanel = New-Object System.Windows.Forms.Panel; $inputPanel.Dock = 'Fill'; $inputPanel.AutoScroll = $true; $split.Panel1.Controls.Add($inputPanel)
$outPanel   = New-Object System.Windows.Forms.Panel; $outPanel.Dock = 'Fill'; $split.Panel2.Controls.Add($outPanel)

$y = 15
function Add-Header([string]$Text) {
    $lbl = New-Object System.Windows.Forms.Label; $lbl.Text = $Text; $lbl.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold); $lbl.ForeColor = $c_blue
    $lbl.Location = New-Object System.Drawing.Point(10, $script:y); $lbl.AutoSize = $true; $inputPanel.Controls.Add($lbl); $script:y += 25
}
function Add-Field([string]$Label, [System.Windows.Forms.Control]$Ctrl) {
    $lbl = New-Object System.Windows.Forms.Label; $lbl.Text = $Label; $lbl.Location = New-Object System.Drawing.Point(15, ($script:y + 3)); $lbl.AutoSize = $true; $inputPanel.Controls.Add($lbl)
    $Ctrl.Location = New-Object System.Drawing.Point(160, $script:y); $Ctrl.Width = 380
    if ($Ctrl -is [System.Windows.Forms.TextBox]) { $Ctrl.BorderStyle = 'FixedSingle' }
    $inputPanel.Controls.Add($Ctrl); $script:y += 30
}

Add-Header "Metadata & Target"
$txtName = New-Object System.Windows.Forms.TextBox; Add-Field "Query Name:" $txtName
$txtTags = New-Object System.Windows.Forms.TextBox; Add-Field "Tags:" $txtTags
$cmbTable = New-Object System.Windows.Forms.ComboBox; $cmbTable.DropDownStyle = 'DropDownList'
foreach ($t in $script:TableDefinitions.Keys | Sort-Object) { [void]$cmbTable.Items.Add($t) }
$cmbTable.SelectedItem = 'SecurityEvent'; Add-Field "Table:" $cmbTable

Add-Header "Standard Filters"
$cmbTime = New-Object System.Windows.Forms.ComboBox; $cmbTime.DropDownStyle = 'DropDownList'
@('1h','4h','24h','7d','30d','all') | ForEach-Object { [void]$cmbTime.Items.Add($_) }; $cmbTime.SelectedItem = '24h'; Add-Field "Time Range:" $cmbTime
$txtComputer = New-Object System.Windows.Forms.TextBox; Add-Field "Computer:" $txtComputer
$txtUser = New-Object System.Windows.Forms.TextBox; Add-Field "User Account:" $txtUser

Add-Header "Advanced Filters (Auto-mapped to Schema)"
$txtIp = New-Object System.Windows.Forms.TextBox; Add-Field "IP Address:" $txtIp
$txtProc = New-Object System.Windows.Forms.TextBox; Add-Field "Process Name:" $txtProc
$txtCmd = New-Object System.Windows.Forms.TextBox; Add-Field "Command Line:" $txtCmd
$txtHash = New-Object System.Windows.Forms.TextBox; Add-Field "File Hash:" $txtHash

Add-Header "Table Specifics"
$specPanel = New-Object System.Windows.Forms.Panel; $specPanel.Location = New-Object System.Drawing.Point(15, $script:y); $specPanel.Size = New-Object System.Drawing.Size(525, 60); $inputPanel.Controls.Add($specPanel); $script:y += 70
$script:SpecificsControls = @{}

Add-Header "Output Configuration"
$lstCols = New-Object System.Windows.Forms.CheckedListBox; $lstCols.Location = New-Object System.Drawing.Point(15, $script:y); $lstCols.Size = New-Object System.Drawing.Size(525, 120); $lstCols.CheckOnClick = $true; $inputPanel.Controls.Add($lstCols); $script:y += 130

$rdoDetailed = New-Object System.Windows.Forms.RadioButton; $rdoDetailed.Text = "Detailed"; $rdoDetailed.Location = New-Object System.Drawing.Point(15, $script:y); $rdoDetailed.Checked = $true; $rdoDetailed.AutoSize=$true; $inputPanel.Controls.Add($rdoDetailed)
$rdoSummarized = New-Object System.Windows.Forms.RadioButton; $rdoSummarized.Text = "Summarized"; $rdoSummarized.Location = New-Object System.Drawing.Point(100, $script:y); $rdoSummarized.AutoSize=$true; $inputPanel.Controls.Add($rdoSummarized)

$lblLimit = New-Object System.Windows.Forms.Label; $lblLimit.Text = "Limit:"; $lblLimit.Location = New-Object System.Drawing.Point(380, ($script:y + 2)); $lblLimit.AutoSize = $true; $inputPanel.Controls.Add($lblLimit)
$numLimit = New-Object System.Windows.Forms.NumericUpDown; $numLimit.Location = New-Object System.Drawing.Point(430, $script:y); $numLimit.Minimum = 0; $numLimit.Maximum = 1000000; $numLimit.Value = 1000; $numLimit.Width = 110; $numLimit.BackColor = $c_bg; $numLimit.ForeColor = $c_textMain; $numLimit.BorderStyle='FixedSingle'; $inputPanel.Controls.Add($numLimit); $script:y += 40

$btnGenerate = New-Object System.Windows.Forms.Button; $btnGenerate.Text = "Build Query"; $btnGenerate.Location = New-Object System.Drawing.Point(15, $script:y); $btnGenerate.Width = 120; $btnGenerate.Height = 35; $inputPanel.Controls.Add($btnGenerate)
$btnSave = New-Object System.Windows.Forms.Button; $btnSave.Text = "Save DB"; $btnSave.Location = New-Object System.Drawing.Point(145, $script:y); $btnSave.Width = 90; $btnSave.Height = 35; $inputPanel.Controls.Add($btnSave)

$txtKql = New-Object System.Windows.Forms.TextBox; $txtKql.Multiline = $true; $txtKql.ScrollBars = 'Both'; $txtKql.Font = $fontMono; $txtKql.WordWrap = $false; $txtKql.Dock = 'Fill'; $txtKql.BorderStyle = 'None'
$outPanel.Controls.Add($txtKql); $txtKql.BringToFront()

# --- TAB 2 (Snort Converter) ---
$snortSplit = New-Object System.Windows.Forms.SplitContainer; $snortSplit.Dock = 'Fill'; $snortSplit.Orientation = 'Horizontal'; $snortSplit.SplitterDistance = 300; $tabSnort.Controls.Add($snortSplit)

$lblSnortIn = New-Object System.Windows.Forms.Label; $lblSnortIn.Text = " Paste Snort Rules (One per line):"; $lblSnortIn.Dock = 'Top'; $lblSnortIn.Height = 25; $lblSnortIn.ForeColor = $c_red; $lblSnortIn.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold); $snortSplit.Panel1.Controls.Add($lblSnortIn)
$txtSnortIn = New-Object System.Windows.Forms.TextBox; $txtSnortIn.Multiline = $true; $txtSnortIn.ScrollBars = 'Both'; $txtSnortIn.Dock = 'Fill'; $txtSnortIn.BorderStyle = 'None'; $txtSnortIn.Font = $fontMono; $snortSplit.Panel1.Controls.Add($txtSnortIn); $txtSnortIn.BringToFront()

$pnlSnortMid = New-Object System.Windows.Forms.Panel; $pnlSnortMid.Dock = 'Bottom'; $pnlSnortMid.Height = 50; $pnlSnortMid.BackColor = $c_elevated; $snortSplit.Panel1.Controls.Add($pnlSnortMid)
$btnConvertSnort = New-Object System.Windows.Forms.Button; $btnConvertSnort.Text = "Convert to KQL"; $btnConvertSnort.Location = New-Object System.Drawing.Point(15, 8); $btnConvertSnort.Width = 160; $btnConvertSnort.Height = 34; $btnConvertSnort.ForeColor = $c_green; $pnlSnortMid.Controls.Add($btnConvertSnort)

$lblSnortOut = New-Object System.Windows.Forms.Label; $lblSnortOut.Text = " Generated Web/L7 KQL:"; $lblSnortOut.Dock = 'Top'; $lblSnortOut.Height = 25; $lblSnortOut.ForeColor = $c_blue; $lblSnortOut.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold); $snortSplit.Panel2.Controls.Add($lblSnortOut)
$txtSnortOut = New-Object System.Windows.Forms.TextBox; $txtSnortOut.Multiline = $true; $txtSnortOut.ScrollBars = 'Both'; $txtSnortOut.Font = $fontMono; $txtSnortOut.WordWrap = $false; $txtSnortOut.Dock = 'Fill'; $txtSnortOut.BorderStyle = 'None'; $snortSplit.Panel2.Controls.Add($txtSnortOut); $txtSnortOut.BringToFront()

Apply-Theme $form

# ================================================================
# EVENT HANDLERS
# ================================================================
$cmbTable.Add_SelectedIndexChanged({
    $def = $script:TableDefinitions[$cmbTable.SelectedItem]
    $specPanel.Controls.Clear(); $script:SpecificsControls = @{}
    $sx = 0; $sy = 0
    foreach ($k in $def.Specifics.Keys) {
        $lbl = New-Object System.Windows.Forms.Label; $lbl.Text = "$k`:"; $lbl.Location = New-Object System.Drawing.Point($sx, ($sy + 3)); $lbl.AutoSize = $true; $lbl.ForeColor = $c_textMain; $specPanel.Controls.Add($lbl)
        $cmb = New-Object System.Windows.Forms.ComboBox; $cmb.Location = New-Object System.Drawing.Point(($sx + 70), $sy); $cmb.Width = 160; $cmb.DropDownStyle='DropDown'; $cmb.BackColor=$c_bg; $cmb.ForeColor=$c_textMain
        foreach ($v in $def.Specifics[$k]) { [void]$cmb.Items.Add($v) }
        $specPanel.Controls.Add($cmb); $script:SpecificsControls[$k] = $cmb
        $sx += 250; if ($sx -gt 400) { $sx = 0; $sy += 30 }
    }
    $lstCols.Items.Clear()
    foreach ($col in $def.AvailableColumns) {
        $idx = $lstCols.Items.Add($col)
        if ($col -in $def.DefaultColumns) { $lstCols.SetItemChecked($idx, $true) }
    }
})
$cmbTable.SelectedIndex = 0

$btnGenerate.Add_Click({
    $specs = @{}; foreach ($k in $script:SpecificsControls.Keys) { $specs[$k] = $script:SpecificsControls[$k].Text }
    $cols = @(); for ($i = 0; $i -lt $lstCols.Items.Count; $i++) { if ($lstCols.GetItemChecked($i)) { $cols += $lstCols.Items[$i] } }
    
    $state = [PSCustomObject]@{
        Name=$txtName.Text; Tags=$txtTags.Text; TableName=$cmbTable.SelectedItem; TimeRange=$cmbTime.SelectedItem
        Computer=$txtComputer.Text; User=$txtUser.Text; F_IP=$txtIp.Text; F_Process=$txtProc.Text; F_Cmd=$txtCmd.Text; F_Hash=$txtHash.Text
        Specifics=$specs; Columns=$cols; OutputMode=if($rdoSummarized.Checked){'Summarized'}else{'Detailed'}; Limit=[int]$numLimit.Value
    }
    $txtKql.Text = Build-KqlQuery -State $state
})

$btnSave.Add_Click({
    if (-not $txtKql.Text -or -not $txtName.Text) { [System.Windows.Forms.MessageBox]::Show("Name and Query required.", "Warning", 0, 48); return }
    Save-Query -Name $txtName.Text -Tags $txtTags.Text -TableName $cmbTable.SelectedItem -KqlText $txtKql.Text
    [System.Windows.Forms.MessageBox]::Show("Query Saved to DB/JSON", "Success", 0, 64) | Out-Null
})

$btnConvertSnort.Add_Click({
    $lines = $txtSnortIn.Text -split "\r?\n" | Where-Object { $_.Trim() -ne '' }
    $kqlOut = ""
    foreach ($rule in $lines) {
        if ($rule -notmatch 'content:|pcre:') { $kqlOut += "// Skipped (Not Layer 7 payload): $rule`r`n`r`n"; continue }
        $msg = "Converted Rule"; if ($rule -match 'msg:\s*"([^"]+)"') { $msg = $Matches[1] }
        
        $kql = "// Snort: $msg`r`nCommonSecurityLog`r`n| where TimeGenerated > ago(1d)`r`n| where DeviceVendor in~ (`"F5`", `"Palo Alto Networks`", `"Blue Coat`", `"Microsoft`", `"CISCO`")`r`n"
        
        foreach ($match in [regex]'(?i)content:\s*"([^"|]+)"'.Matches($rule)) {
            $val = $match.Groups[1].Value
            if ($val -match "^(POST|GET|PUT|DELETE|PATCH)\s+(.*)") {
                $kql += "| where RequestMethod =~ `"$($Matches[1])`"`r`n"
                if ($Matches[2].Trim()) { $kql += "| where RequestURL contains `"$($Matches[2].Trim())`"`r`n" }
            } elseif ($val -match "^(POST|GET|PUT|DELETE|PATCH)$") { $kql += "| where RequestMethod =~ `"$val`"`r`n" }
            else { $kql += "| where RequestURL contains `"$val`" or AdditionalExtensions contains `"$val`" or Message contains `"$val`"`r`n" }
        }
        $pcre = [regex]'(?i)pcre:\s*"([^"]+)"'.Match($rule)
        if ($pcre.Success) {
            $clean = $pcre.Groups[1].Value -replace '^/|/[a-zA-Z]*$', ''
            $kql += "| where RequestURL matches regex @`"$clean`" or AdditionalExtensions matches regex @`"$clean`" or Message matches regex @`"$clean`"`r`n"
        }
        $kql += "| project TimeGenerated, DeviceVendor, SourceIP, DestinationIP, RequestMethod, RequestURL, AdditionalExtensions`r`n`r`n"
        $kqlOut += $kql
    }
    $txtSnortOut.Text = $kqlOut
})

$form.Add_HandleCreated({
    $useImmersiveDarkMode = 1
    # 20 is DWMWA_USE_IMMERSIVE_DARK_MODE for Windows 11 (and newer Win 10)
    [DarkModeTheme]::DwmSetWindowAttribute($form.Handle, 20, [ref]$useImmersiveDarkMode, 4) | Out-Null
    # Try 19 for older Windows 10 builds just in case
    [DarkModeTheme]::DwmSetWindowAttribute($form.Handle, 19, [ref]$useImmersiveDarkMode, 4) | Out-Null
})

[void]$form.ShowDialog()
