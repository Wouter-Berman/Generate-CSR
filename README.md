# Generate-CSR
Powershell tool to generate a Certificate Signing Request (CSR) using a GUI interface

I have been looking for a Windows GUI tool to create certificate signing requests which would allow for Subject Alt names. DigiCert Certificate Utility for Windows provides such functionality but uses a hashing algorithm which is not secure anymore. There are several Powershell scripts with this functionality, but none provide a GUI. So I decided to write my own. As PowerShell does not include functionality to generate a CSR the script is using CertReq.exe which is included on Windows Machines by default.

# Usage
Just run Generate-CSR.ps1 with powershell. The following GUI will be presented:

![Image of GUI](/images/gui.png)

Only the common name is a required field. All other fields are optional. If you do not know what to select for Key size and Hash Algorithm just leave the values unchanged. They are fine for normal use. Enter the information you want to include in the certificate and hit "Generate CSR". You will be asked to provide a name and location for the generated CSR file:

![Image of save file dialog](/images/dialog.png)

Generating a CSR on a Windows machine requires administrative permissions. If PowerShell was not started with admin privileges a popup will be shown to allow the creation of the CSR:

![Image of User Account Control dialog](/images/uac.png)

The generated CSR is shown in the GUI window and saved to the specified file. You can use the CSR to request a certificate from a certificate provider of your choice. The certificate key is stored safely within the certificate store on your PC under Certificate Enrollment Requests:

![Image of Computer Certificate Store](/images/certstore.png)

When you receive the certificate in a .cer or .crt file from your certificate provider you can install it. After installation the new certificate (including the key) can be found in the Computer Certificate Store under Personal/Certificates.

# Dependencies
This script uses CertReq.exe which exists by default on any (recent) Windows machine.
