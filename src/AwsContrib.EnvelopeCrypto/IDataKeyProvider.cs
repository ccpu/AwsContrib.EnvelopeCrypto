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
using System.Collections.Generic;

namespace AwsContrib.EnvelopeCrypto
{
	public interface IDataKeyProvider
	{
		void GenerateKey(int keyBits, out byte[] key, out byte[] encryptedKey);

		void GenerateKey(int keyBits, out byte[] key, out byte[] encryptedKey, IDictionary<string, string> context);

		byte[] EncryptKey(byte[] plainText);

		byte[] EncryptKey(byte[] plainText, IDictionary<string, string> context);

		byte[] DecryptKey(byte[] cipherText);

		byte[] DecryptKey(byte[] cipherText, IDictionary<string, string> context);
	}
}