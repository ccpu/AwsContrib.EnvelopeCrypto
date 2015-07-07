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
using System.Security.Cryptography;

namespace AwsContrib.EnvelopeCrypto.Internal
{
	// Allows mocking SymmetricAlgorithm in tests.
	internal interface ISymmetricAlgorithm : IDisposable
	{
		int BlockSize { get; set; }
		int FeedbackSize { get; set; }
		byte[] IV { get; set; }
		byte[] Key { get; set; }
		KeySizes[] LegalBlockSizes { get; }
		KeySizes[] LegalKeySizes { get; }
		int KeySize { get; set; }
		CipherMode Mode { get; set; }
		PaddingMode Padding { get; set; }

		int KeyBits { get; }
		int BlockBytes { get; }

		void Clear();

		bool ValidKeySize(int bitLength);

		ICryptoTransform CreateEncryptor();

		ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV);

		ICryptoTransform CreateDecryptor();

		ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV);

		void GenerateKey();

		void GenerateIV();
	}
}