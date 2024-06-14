#Create cert and store in cert store in Windows
$cert=New-SelfSignedCertificate -Subject "CN=GraphDaemonWithCert" -CertStoreLocation "Cert:\CurrentUser\My"  -KeyExportPolicy Exportable -KeySpec Signature

#extract pfx
$certThumbprint = "961c4416a321a0d587fbbc10b38626c9542526fe" # YOUR CERTIFICATE THUMBPRINT
$cert = Get-ChildItem -Path Cert:\CurrentUser\My\$certThumbprint
$certPassword = ConvertTo-SecureString -String "YOUR PASSSWORD GOES HERE, THIS IS A PLACEHODLER!" -Force -AsPlainText # YOUR PASSWORD
Export-PfxCertificate -Cert $cert -FilePath "D:\certificate.pfx" -Password $certPassword

#Import the certificate pfx to azure keyvault using azure portal keyvault ui or az cli/powershell