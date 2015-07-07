#region license
//
// Copyright 2015 ICA.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#endregion
using System.Configuration;

using Amazon;
using Amazon.KeyManagementService;

using FluentAssertions;

using NUnit.Framework;

namespace AwsContrib.EnvelopeCrypto.IntegrationTests
{
	public class CryptoProviderTests
	{
		[Test]
		public void RoundTrip_Ok()
		{
			// Depends on client being configured in app.config or ambient environment.
			IAmazonKeyManagementService client = AWSClientFactory.CreateAmazonKeyManagementServiceClient();

			string keyid = ConfigurationManager.AppSettings["kmsKeyId"];
			ICryptoProvider crypto = new EnvelopeCryptoProvider(client, keyid);

			const string plaintext = "Peek-a-boo!";
			string dataKey;
			string ciphertext = crypto.Encrypt(out dataKey, plaintext);

			dataKey.Should().NotBeEmpty();
			ciphertext.Should().NotBe(plaintext);

			string decrypted = crypto.Decrypt(dataKey, ciphertext);
			decrypted.Should().Be("Peek-a-boo!");
		}
	}
}