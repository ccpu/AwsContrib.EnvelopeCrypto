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
using System;
using System.Collections.Generic;
using System.IO;

using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;

namespace AwsContrib.EnvelopeCrypto
{
	public class KmsDataKeyProvider : IDataKeyProvider
	{
		private readonly IAmazonKeyManagementService _client;
		private readonly string _keyId;

		public KmsDataKeyProvider(IAmazonKeyManagementService keyManagementService, string keyId)
		{
			_client = keyManagementService;
			_keyId = keyId;
		}

		public void GenerateKey(int keyBits, out byte[] key, out byte[] encryptedKey)
		{
			GenerateKey(keyBits, out key, out encryptedKey, new Dictionary<string, string>());
		}

		public void GenerateKey(int keyBits, out byte[] key, out byte[] encryptedKey, IDictionary<string, string> context)
		{
			DataKeySpec keySpec;
			if (keyBits == 128)
			{
				keySpec = DataKeySpec.AES_128;
			}
			else if (keyBits == 256)
			{
				keySpec = DataKeySpec.AES_256;
			}
			else
			{
				throw new ArgumentException("only 128 and 256 bit keys are supported", "keyBits");
			}
			var request = new GenerateDataKeyRequest
			{
				KeyId = _keyId,
				KeySpec = keySpec,
				EncryptionContext = AsDictionary(context)
			};
			GenerateDataKeyResponse response = _client.GenerateDataKey(request);

			key = response.Plaintext.ToArray();
			encryptedKey = response.CiphertextBlob.ToArray();
		}

		public byte[] EncryptKey(byte[] plainText)
		{
			return EncryptKey(plainText, new Dictionary<string, string>());
		}

		public byte[] EncryptKey(byte[] plainText, IDictionary<string, string> context)
		{
			var req = new EncryptRequest
			{
				KeyId = _keyId,
				Plaintext = new MemoryStream(plainText),
				EncryptionContext = AsDictionary(context)
			};
			return _client.Encrypt(req).CiphertextBlob.ToArray();
		}

		public byte[] DecryptKey(byte[] cipherText)
		{
			return DecryptKey(cipherText, new Dictionary<string, string>());
		}

		public byte[] DecryptKey(byte[] cipherText, IDictionary<string, string> context)
		{
			var req = new DecryptRequest
			{
				CiphertextBlob = new MemoryStream(cipherText),
				EncryptionContext = AsDictionary(context)
			};
			return _client.Decrypt(req).Plaintext.ToArray();
		}

		private static Dictionary<string, string> AsDictionary(IDictionary<string, string> self)
		{
			var dict = self as Dictionary<string, string>;
			if (self == null || dict == null)
			{
				return new Dictionary<string, string>();
			}
			return dict;
		}
	}
}