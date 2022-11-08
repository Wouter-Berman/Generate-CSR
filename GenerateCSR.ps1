# Powershell tool to generate a Certificate Signing Request (CSR) using a GUI interface
# Written by Wouter Berman (2at - www.2at.nl)
# Published under the GNU General Public License v3.0

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

# Function to show a Save File Dialog and return the path.
function Read-SaveFileDialog {
    $SaveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $SaveFileDialog.InitialDirectory = $pwd.Path
    $SaveFileDialog.Title = 'Save CSR file'
    $SaveFileDialog.Filter = 'txt files (*.txt)|*.txt|All files (*.*)|*.*'
    $SaveFileDialog.ShowHelp = $true
    $SaveFileDialog.OverwritePrompt = $false
    $SaveFileDialog.ShowDialog() | Out-Null
    return $SaveFileDialog.Filename
}

function SaveRecentCSR {
    if ( $null -eq (Get-Item -Path HKCU:\Software\GenerateCSR -ErrorAction:SilentlyContinue)  ) {
        New-Item -Path HKCU:\Software\GenerateCSR
    }

    foreach ( $b in ( 4, 3, 2, 1, 0) ) {
        if ( $b -eq 4) {
            Remove-ItemProperty -Path HKCU:\Software\GenerateCSR -Name "Recent$b" -ErrorAction SilentlyContinue
        }
        else {
            Rename-ItemProperty -Path HKCU:\Software\GenerateCSR -Name "Recent$b" -NewName "Recent$($b+1)" -ErrorAction SilentlyContinue
        }
    }

    $jsonstring = "
[
    {
        `"CN`": `"$($TextBoxCN.Text)`",
        `"OU`": `"$($TextBoxOU.Text)`",
        `"O`": `"$($TextBoxO.Text)`",
        `"L`": `"$($TextBoxL.Text)`",
        `"S`": `"$($TextBoxS.Text)`",
        `"C`": `"$($TextBoxCO.Text)`",
        `"SAN`": `"$($TextBoxSAN.Text)`"
    }
]"
    $json = $jsonstring | ConvertFrom-Json 
    $jsonstringcompressed = $json | ConvertTo-Json -Compress

    Set-ItemProperty -Path Registry::HKEY_CURRENT_USER\Software\GenerateCSR -Name Recent0 -Value $jsonstringcompressed
}

function LoadRecentCSR {
    param (
        $recentitem
    )
    $recentname = "Recent" + ($recentitem - 1)
    $jsonstring = (Get-ItemProperty -Path Registry::HKEY_CURRENT_USER\Software\GenerateCSR -Name $recentname).$recentname
    $json = $jsonstring | Convertfrom-Json

    $TextBoxCN.Text = $json[0].CN
    $TextBoxOU.Text = $json[0].OU
    $TextBoxO.Text = $json[0].O
    $TextBoxL.Text = $json[0].L
    $TextBoxS.Text = $json[0].S
    $TextBoxCO.Text = $json[0].C
    $TextBoxSAN.Text = $json[0].SAN

    return $json
}

function ComboBoxHistorySelectedValueChanged {
    if ( $ComboBoxHistory.SelectedItem -eq '(new)') {
        $TextBoxCN.Text = ""
        $TextBoxOU.Text = ""
        $TextBoxO.Text = ""
        $TextBoxL.Text = ""
        $TextBoxS.Text = ""
        $TextBoxCO.Text = ""
    }
    else {
        LoadRecentCSR $ComboBoxHistory.SelectedIndex
    }
}

function Get-SubjectPart ($subject, $part) {
    $subs = $subject -split ','
    for ($i = 0; $i -lt $subs.Length; $i++) { 
        $sub = $subs[$i]
        if ( $sub.IndexOf( '"' ) -ne -1 ) {
            $nextsub = $subs[$i + 1]
            $sub = "$sub,$nextsub" 
            $sub = $sub.Replace( '"', '')
            $subs[$i + 1] = ''
        }
        $subs[$i] = $sub.Trim(' ')
    }

    $parts = $subs | where { $_ -ne '' }
    (($parts | where { $_ -like "$part=*" }) -split "=")[1]
}

function FetchURL {
    $URL = [uri]$TextBoxURL.Text
    if ( $URL.Scheme -ne "https") {
        $URL = [uri]"https://$($TextBoxURL.Text)"
    }
    $Certificate = $null
    $TcpClient = New-Object -TypeName System.Net.Sockets.TcpClient
    try {

        $TcpClient.Connect($URL.DnsSafeHost, $URL.Port)
        $TcpStream = $TcpClient.GetStream()

        $Callback = { param($sender, $cert, $chain, $errors) return $true }

        $SslStream = New-Object -TypeName System.Net.Security.SslStream -ArgumentList @($TcpStream, $true, $Callback)
        try {
            $xc = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
            $TLS12Protocol = [System.Net.SecurityProtocolType] 'Tls12'
            $sslStream.AuthenticateAsClient($URL.DnsSafeHost, $xc, $TLS12Protocol, $false);
            $Certificate = $SslStream.RemoteCertificate

        }
        finally {
            $SslStream.Dispose()
        }

    }
    finally {
        $TcpClient.Dispose()
    }

    if ($Certificate) {
        if ($Certificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
            $Certificate = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $Certificate
        }
        $infsubject = $Certificate.Subject
        $TextBoxCN.Text = Get-SubjectPart $infsubject 'CN'
        $TextBoxO.Text = Get-SubjectPart $infsubject 'O'
        $TextBoxOU.Text = Get-SubjectPart $infsubject 'OU'
        $TextBoxL.Text = Get-SubjectPart $infsubject 'L'
        $TextBoxS.Text = Get-SubjectPart $infsubject 'S'
        $TextBoxCO.Text = Get-SubjectPart $infsubject 'C'
        
        $sanentries = ($Certificate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.17" }).Format(1)
        $sanentries = $sanentries -Split ([Environment]::NewLine)
        $singleline = ""
        $sanentries | % { $singleline += ($_ -split '=')[1]; $singleline += [Environment]::NewLine } 
        $TextBoxSAN.Text = $singleline
    }
    
}
# Function to create a CSR using CertReq
function CreateCSR {
    $InfFile = New-TemporaryFile
    $CsrFile = Read-SaveFileDialog

    If ($CsrFile) {

        $SAN = "[Extensions]`r`n2.5.29.17  = `"{text}`""
        $i = 1
        While ($i -le $TextBoxSAN.Lines.Count) {
            if ( $TextBoxSAN.Lines[$i - 1] -match '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$' ) {
                $SAN = $SAN + "`r`n_continue_ = `"ipaddress=$($TextBoxSAN.Lines[$i-1])`&`""
            }
            else {
                $SAN = $SAN + "`r`n_continue_ = `"dns=$($TextBoxSAN.Lines[$i-1])`&`""
            }
            $i++
        }

        $InfData = '[Version]'
        $InfData += "`r`nSignature = `"`$Windows NT`$`""
        $InfData += "`r`n`r`n[NewRequest]"
        $InfData += "`r`nSubject = `"CN=$($TextBoxCN.Text), OU=$($TextBoxOU.Text), O=$($TextBoxO.Text), L=$($TextBoxL.Text), S=$($TextBoxS.Text), C=$($TextBoxCO.Text)`""
        $InfData += "`r`nKeyLength = $($ComboBoxKeySize.SelectedItem)"
        $InfData += "`r`nKeySpec = 1"
        $InfData += "`r`nExportable = TRUE"
        $InfData += "`r`nSilent = TRUE"
        $InfData += "`r`nMachineKeySet = TRUE"
        $InfData += "`r`nSMIME = False"
        $InfData += "`r`nPrivateKeyArchive = FALSE"
        $InfData += "`r`nUserProtected = FALSE"
        $InfData += "`r`nUseExistingKeySet = FALSE"
        $InfData += "`r`nProviderName = `"Microsoft RSA SChannel Cryptographic Provider`""
        $InfData += "`r`nProviderType = 12"
        $InfData += "`r`nRequestType = PKCS10"
        $InfData += "`r`nKeyUsage = CERT_DIGITAL_SIGNATURE_KEY_USAGE | CERT_KEY_ENCIPHERMENT_KEY_USAGE"
        $InfData += "`r`nHashAlgorithm = $($ComboBoxHashAlgorithm.SelectedItem)"
        $InfData += "`r`n`r`n[EnhancedKeyUsageExtension]`r`nOID=1.3.6.1.5.5.7.3.1`r`nOID=1.3.6.1.5.5.7.3.2"
        If ($TextBoxSAN.Lines.Count -gt 0) {
            $InfData += "`r`n`r`n$($SAN)"
        }
        $InfData | Out-File -Append -FilePath $InfFile.PSPath
        # CertReq requires elevation. So let's run elevated
        if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Start-Process -wait -Verb RunAs certreq -ArgumentList "-new `"$InfFile`" `"$CsrFile`""
        }
        else {
            certreq -new "$InfFile" "$CsrFile"
        }

        SaveRecentCSR
    }
    If ($InfFile) {
        Remove-Item $InfFile
    }
    $TextBoxCSR.Text = Get-Content $CsrFile
    $CopyButton.Enabled = $true
    $CancelButton.Text = "Close"
}

# Create the form
$Form = New-Object system.Windows.Forms.Form
$Form.Size = New-Object System.Drawing.Size(980, 500)
$form.Font = New-Object System.Drawing.Font("Arial", 11, [System.Drawing.FontStyle]::regular)
$form.MaximizeBox = $false
$Form.StartPosition = "CenterScreen"
$Form.FormBorderStyle = 'Fixed3D'
$Form.Text = "Create CSR"
$Form.WindowState = "Normal"

$LabelHistory = New-Object System.Windows.Forms.Label
$LabelHistory.Text = "History:"
$LabelHistory.AutoSize = $true
$LabelHistory.Location = New-Object System.Drawing.Size(105, 20)
$Form.Controls.Add($LabelHistory)

$ComboBoxHistory = New-Object System.Windows.Forms.ComboBox
$ComboBoxHistory.Location = New-Object System.Drawing.Point(167, 20)
$ComboBoxHistory.Size = New-Object System.Drawing.Size(260, 30)
$ComboBoxHistory.DropDownHeight = 200
$form.Controls.Add($ComboBoxHistory)
$ComboBoxHistory.Items.Add('(new)') | out-null
for ($i = 0; $i -lt 5; $i++) {
    $jsonstring = Get-ItemProperty -Path Registry::HKEY_CURRENT_USER\Software\GenerateCSR -Name "Recent$i" -ErrorAction SilentlyContinue
    if ( $null -ne $jsonstring) {
        $jsonstring = $jsonstring."Recent$i"
        $json = $jsonstring | Convertfrom-Json
        if ( $null -ne $json ) {
            $ComboBoxHistory.Items.Add($json[0].CN) | out-null
        }
    }
}

$ComboBoxHistory.SelectedItem = $ComboBoxHistory.Items[0]
$ComboBoxHistory.Add_SelectedValueChanged({ ComboBoxHistorySelectedValueChanged })


$LabelCN = New-Object System.Windows.Forms.Label
$LabelCN.Text = "Common name:*"
$LabelCN.AutoSize = $true
$LabelCN.Location = New-Object System.Drawing.Size(49, 50)
$Form.Controls.Add($LabelCN)

$TextBoxCN = New-Object System.Windows.Forms.TextBox
$TextBoxCN.Location = New-Object System.Drawing.Point(167, 47)
$TextBoxCN.Size = New-Object System.Drawing.Size(260, 20)
$form.Controls.Add($TextBoxCN)

$LabelSAN = New-Object System.Windows.Forms.Label
$LabelSAN.Text = "Subject alt names:"
$LabelSAN.AutoSize = $true
$LabelSAN.Location = New-Object System.Drawing.Size(35, 80)
$Form.Controls.Add($LabelSAN)

$TextBoxSAN = New-Object System.Windows.Forms.TextBox
$TextBoxSAN.Location = New-Object System.Drawing.Point(167, 77)
$TextBoxSAN.Size = New-Object System.Drawing.Size(260, 99)
$TextBoxSAN.Multiline = $True;
$TextBoxSAN.Scrollbars = "Vertical"
$form.Controls.Add($TextBoxSAN)

$LabelO = New-Object System.Windows.Forms.Label
$LabelO.Text = "Organization:"
$LabelO.AutoSize = $true
$LabelO.Location = New-Object System.Drawing.Size(69, 185)
$Form.Controls.Add($LabelO)

$TextBoxO = New-Object System.Windows.Forms.TextBox
$TextBoxO.Location = New-Object System.Drawing.Point(167, 182)
$TextBoxO.Size = New-Object System.Drawing.Size(260, 20)
$form.Controls.Add($TextBoxO)

$LabelOU = New-Object System.Windows.Forms.Label
$LabelOU.Text = "Department:"
$LabelOU.AutoSize = $true
$LabelOU.Location = New-Object System.Drawing.Size(74, 215)
$Form.Controls.Add($LabelOU)

$TextBoxOU = New-Object System.Windows.Forms.TextBox
$TextBoxOU.Location = New-Object System.Drawing.Point(167, 212)
$TextBoxOU.Size = New-Object System.Drawing.Size(260, 20)
$form.Controls.Add($TextBoxOU)

$LabelL = New-Object System.Windows.Forms.Label
$LabelL.Text = "City:"
$LabelL.AutoSize = $true
$LabelL.Location = New-Object System.Drawing.Size(125, 245)
$Form.Controls.Add($LabelL)

$TextBoxL = New-Object System.Windows.Forms.TextBox
$TextBoxL.Location = New-Object System.Drawing.Point(167, 242)
$TextBoxL.Size = New-Object System.Drawing.Size(260, 20)
$form.Controls.Add($TextBoxL)

$LabelS = New-Object System.Windows.Forms.Label
$LabelS.Text = "State:"
$LabelS.AutoSize = $true
$LabelS.Location = New-Object System.Drawing.Size(117, 275)
$Form.Controls.Add($LabelS)

$TextBoxS = New-Object System.Windows.Forms.TextBox
$TextBoxS.Location = New-Object System.Drawing.Point(167, 272)
$TextBoxS.Size = New-Object System.Drawing.Size(260, 20)
$form.Controls.Add($TextBoxS)

$LabelCO = New-Object System.Windows.Forms.Label
$LabelCO.Text = "Country:"
$LabelCO.AutoSize = $true
$LabelCO.Location = New-Object System.Drawing.Size(99, 305)
$Form.Controls.Add($LabelCO)

$TextBoxCO = New-Object System.Windows.Forms.TextBox
$TextBoxCO.Location = New-Object System.Drawing.Point(167, 302)
$TextBoxCO.Size = New-Object System.Drawing.Size(260, 20)
$form.Controls.Add($TextBoxCO)

$LabelKeySize = New-Object System.Windows.Forms.Label
$LabelKeySize.Text = "Key size:"
$LabelKeySize.AutoSize = $true
$LabelKeySize.Location = New-Object System.Drawing.Size(96, 335)
$Form.Controls.Add($LabelKeySize)

$ComboBoxKeySize = New-Object System.Windows.Forms.ComboBox
$ComboBoxKeySize.Location = New-Object System.Drawing.Point(167, 332)
$ComboBoxKeySize.Size = New-Object System.Drawing.Size(260, 30)
$ComboBoxKeySize.DropDownHeight = 200
$form.Controls.Add($ComboBoxKeySize)
$ComboBoxKeySize.Items.Add('2048') | out-null
$ComboBoxKeySize.Items.Add('4096') | out-null
$ComboBoxKeySize.Items.Add('8192') | out-null
$ComboBoxKeySize.SelectedItem = $ComboBoxKeySize.Items[0]

$LabelHashAlgorithm = New-Object System.Windows.Forms.Label
$LabelHashAlgorithm.Text = "Hash algorithm:"
$LabelHashAlgorithm.AutoSize = $true
$LabelHashAlgorithm.Location = New-Object System.Drawing.Size(53, 365)
$Form.Controls.Add($LabelHashAlgorithm)

$ComboBoxHashAlgorithm = New-Object System.Windows.Forms.ComboBox
$ComboBoxHashAlgorithm.Location = New-Object System.Drawing.Point(167, 362)
$ComboBoxHashAlgorithm.Size = New-Object System.Drawing.Size(260, 20)
$ComboBoxHashAlgorithm.DropDownHeight = 200
$form.Controls.Add($ComboBoxHashAlgorithm)
$ComboBoxHashAlgorithm.Items.Add('sha256') | out-null
$ComboBoxHashAlgorithm.Items.Add('sha384') | out-null
$ComboBoxHashAlgorithm.Items.Add('sha512') | out-null
$ComboBoxHashAlgorithm.SelectedItem = $ComboBoxHashAlgorithm.Items[0]

$ButtonFetchURL = New-Object System.Windows.Forms.Button
$ButtonFetchURL.Location = New-Object System.Drawing.Size(450, 20)
$ButtonFetchURL.Size = New-Object System.Drawing.Size(120, 23)
$ButtonFetchURL.Text = "< Fill from URL"
$ButtonFetchURL.Add_Click({ FetchURL })
$Form.Controls.Add($ButtonFetchURL)

$TextBoxURL = New-Object System.Windows.Forms.TextBox
$TextBoxURL.Location = New-Object System.Drawing.Point(580, 20)
$TextBoxURL.Size = New-Object System.Drawing.Size(350, 20)
$form.Controls.Add($TextBoxURL)

$LabelCSR = New-Object System.Windows.Forms.Label
$LabelCSR.Text = "CSR:"
$LabelCSR.AutoSize = $true
$LabelCSR.Location = New-Object System.Drawing.Size(450, 56)
$Form.Controls.Add($LabelCSR)

$TextBoxCSR = New-Object System.Windows.Forms.TextBox
$TextBoxCSR.Location = New-Object System.Drawing.Point(450, 80)
$TextBoxCSR.Size = New-Object System.Drawing.Size(480, 308)
$TextBoxCSR.Multiline = $true
$TextBoxCSR.ReadOnly = $true
$TextBoxCSR.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::regular)
$form.Controls.Add($TextBoxCSR)

$CreateCSRbutton = New-Object System.Windows.Forms.Button
$CreateCSRButton.Location = New-Object System.Drawing.Size(308, 400)
$CreateCSRButton.Size = New-Object System.Drawing.Size(120, 30)
$CreateCSRButton.Text = "Create CSR"
$CreateCSRButton.Add_Click({ CreateCSR })
$Form.Controls.Add($CreateCSRButton)

$Copybutton = New-Object System.Windows.Forms.Button
$CopyButton.Location = New-Object System.Drawing.Size(670, 400)
$CopyButton.Size = New-Object System.Drawing.Size(120, 30)
$CopyButton.Text = "Copy CSR"
$CopyButton.Add_Click({ $TextBoxCSR.text | Clip })
$Copybutton.Enabled = $false
$Form.Controls.Add($CopyButton)

$Cancelbutton = New-Object System.Windows.Forms.Button
$CancelButton.Location = New-Object System.Drawing.Size(810, 400)
$CancelButton.Size = New-Object System.Drawing.Size(120, 30)
$CancelButton.Text = "Cancel"
$CancelButton.Add_Click({ $Form.Close() })
$Form.Controls.Add($CancelButton)

# Show the form
$Form.ShowDialog() | Out-Null



