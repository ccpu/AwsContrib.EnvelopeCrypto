AwsContrib.EnvelopeCrypto
=========================

A library for using AWS KMS (Key Management Service) to do envelope
cryptography. This allows you to encrypt large payloads without exposing
your secrets to Amazon or transferring large objects over the network.

See [Amazon's developer
guide](http://docs.aws.amazon.com/kms/latest/developerguide/workflow.html)
regarding envelope encryption.

How to use it
=============

First, create an encryption key using the AWS console or API. You will need to grant the following permissions against this key to the user whose API credentials you will be using:

* kms:Decrypt
* kms:Encrypt
* kms:GenerateDataKey

Next, create a KMS client and use it to create an EnvelopeCryptoProvider.

	var client = Amazon.AWSClientFactory.CreateAmazonKeyManagementServiceClient();
	var crypto = new EnvelopeCryptoProvider(client, "alias/MyKeyAlias");

To encrypt data, use one of the Encrypt() overloads.	
	string dataKey;
	string encrypted = crypto.Encrypt(out dataKey, "s3cr3t!");

The data key is also encrypted and does not need to be kept secret. You should store it alongside the encrypted data, since you will need it later for decryption:

	string decrypted = crypto.Decrypt(dataKey, encrypted);
	Console.WriteLine(decrypted); // "s3cr3t!"

