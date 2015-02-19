param(
	 [Parameter(Mandatory=$True)]
	 [ValidateNotNull()]
	 [String]
	 $accessKeyId,
	 
	 [Parameter(Mandatory=$True)]
	 [ValidateNotNull()]
	 [String]
     $secretAccessKey,
	 
	 [Parameter(Mandatory=$True)]
	 [ValidateNotNull()]
	 [String]
     $region,

	 [Parameter(Mandatory=$True)]
	 [ValidateNotNull()]
	 [String]
     $kmsKeyId
)

$dir = pwd
$filename = "$($dir)\bin\Debug\AwsContrib.EnvelopeCrypto.IntegrationTests.dll.config"

$config = [xml](Get-Content $filename)

Function AddConfig($key,$val)
{
    $node = $config.CreateElement("add")
    $node.SetAttribute("key", $key)
    $node.SetAttribute("value", $val)
    $config.configuration.appSettings.AppendChild($node) | out-null
}


$clobber = "AWSAccessKey", "AWSSecretKey", "AWSProfileName", "AWSRegion", "kmsKeyId"

foreach ($node in $config.selectNodes("//appSettings/add"))
{
    if ($clobber -contains $node.key)
    {
        $config.configuration.appSettings.RemoveChild($node) | out-null
    }
}

AddConfig -key "AWSAccessKey" -val $accessKeyId
AddConfig -key "AWSSecretKey" -val $secretAccessKey
AddConfig -key "AWSRegion" -val $region
AddConfig -key "kmsKeyId" -val $kmsKeyId

$config.save($filename)