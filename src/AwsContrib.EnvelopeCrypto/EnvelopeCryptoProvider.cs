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
using System.Linq;
using System.Security.Cryptography;
using System.Text;

using Amazon.KeyManagementService;

using AwsContrib.EnvelopeCrypto.Internal;

namespace AwsContrib.EnvelopeCrypto
{
	public class EnvelopeCryptoProvider : ICryptoProvider
	{
		private static readonly IEnvelopeCryptoConfig _defaultConfig = new DefaultEnvelopeCryptoConfig();
		private static readonly Encoding _binaryEncoding = Encoding.GetEncoding("iso-8859-1");
		private readonly IAlgorithmFactory _algorithmFactory;
		private readonly IEnvelopeCryptoConfig _config;
		private readonly IDataKeyProvider _dataKeyProvider;

		internal EnvelopeCryptoProvider(IDataKeyProvider dataKeyProvider, IEnvelopeCryptoConfig config, IAlgorithmFactory algorithmFactory)
		{
			if (dataKeyProvider == null)
			{
				throw new ArgumentNullException("dataKeyProvider");
			}
			_dataKeyProvider = dataKeyProvider;
			_config = config;
			_algorithmFactory = algorithmFactory;
		}

		/// <param name="keyService">An Amazon KMS service client</param>
		/// <param name="keyId">The id or alias of the KMS master key to use</param>
		public EnvelopeCryptoProvider(IAmazonKeyManagementService keyService, string keyId)
			: this(new KmsDataKeyProvider(keyService, keyId)) {}

		/// <param name="keyService">An Amazon KMS service client</param>
		/// <param name="keyId">The id or alias of the KMS master key to use</param>
		/// <param name="cacheSize">The number of decrypted keys to cache in RAM</param>
		public EnvelopeCryptoProvider(IAmazonKeyManagementService keyService, string keyId, int cacheSize)
			: this(new CachingDataKeyProvider(new KmsDataKeyProvider(keyService, keyId), cacheSize)) {}

		public EnvelopeCryptoProvider(IDataKeyProvider dataKeyProvider)
			: this(dataKeyProvider, new DefaultEnvelopeCryptoConfig(), new DefaultAlgorithmFactory()) {}

		public EnvelopeCryptoProvider(IEnvelopeCryptoConfig config, IDataKeyProvider dataKeyProvider)
			: this(dataKeyProvider, config, new DefaultAlgorithmFactory()) {}

		public static string AlgorithmName
		{
			get { return _defaultConfig.AlgorithmName; }
		}

		public static int KeyBits
		{
			get { return _defaultConfig.KeyBits; }
		}

		public static int BlockBytes
		{
			get { return _defaultConfig.BlockBytes; }
		}

		public static int IVBytes
		{
			get { return _defaultConfig.IVBytes; }
		}

		public static CipherMode Mode
		{
			get { return _defaultConfig.Mode; }
		}

		public static PaddingMode Padding
		{
			get { return _defaultConfig.Padding; }
		}

		public byte[] Encrypt(out byte[] dataKey, byte[] plaintextBlob, IDictionary<string, string> context)
		{
			return Encrypt(out dataKey, new[] {plaintextBlob}, context).Single();
		}

		public byte[] Encrypt(out byte[] dataKey, byte[] plaintextBlob)
		{
			return Encrypt(out dataKey, new[] {plaintextBlob}, null).Single();
		}

		public Stream Encrypt(out byte[] dataKey, Stream plaintextStream)
		{
			return Encrypt(out dataKey, plaintextStream, null);
		}

		public Stream Encrypt(out byte[] dataKey, Stream plaintextStream, IDictionary<string, string> context)
		{
			byte[] plaintextKey;
			_dataKeyProvider.GenerateKey(_config.KeyBits, out plaintextKey, out dataKey, context);

			ISymmetricAlgorithm algo = null;
			try
			{
				algo = _algorithmFactory.CreateAlgorithm(_config);
				algo.Key = plaintextKey;
				algo.GenerateIV();

				// All these hoops with the concatenated streams, StreamWithDisposable, etc.
				// are to support: using (Stream foo = provider.Encrypt(...)) {...}
				ICryptoTransform encryptor = algo.CreateEncryptor();
				Stream ivStream = new MemoryStream(algo.IV);
				Stream cryptoStream = new CryptoStream(plaintextStream, encryptor, CryptoStreamMode.Read);
				Stream streamPair = new ConcatenatedStream(ivStream, cryptoStream);

				// when this stream is disposed, so will be all of its constituent streams,
				// plus the algorithm and the encryptor.
				return new StreamWithDisposables(streamPair, new IDisposable[] {algo, encryptor});
			}
			catch (Exception e)
			{
				// If we had trouble creating the stream, destroy the algorithm to prevent the key leaking.
				if (algo != null)
				{
					try
					{
						algo.Dispose();
					}
					catch (Exception disposalException)
					{
						throw new AggregateException(e, disposalException);
					}
				}
				throw;
			}
		}

		public IEnumerable<byte[]> Encrypt(out byte[] dataKey, IEnumerable<byte[]> plaintextBlobs, IDictionary<string, string> context)
		{
			byte[] plaintextKey;
			_dataKeyProvider.GenerateKey(_config.KeyBits, out plaintextKey, out dataKey, context);

			using (ISymmetricAlgorithm algo = _algorithmFactory.CreateAlgorithm(_config))
			{
				algo.Key = plaintextKey;
				algo.GenerateIV();
				return plaintextBlobs.Select(blob => Encrypt(algo, blob)).ToList();
			}
		}

		public IEnumerable<byte[]> Encrypt(out byte[] dataKey, IEnumerable<byte[]> plaintextBlobs)
		{
			return Encrypt(out dataKey, plaintextBlobs, null);
		}

		public string Encrypt(out string dataKey, string plaintext, IDictionary<string, string> context)
		{
			return Encrypt(out dataKey, new[] {plaintext}, context).Single();
		}

		public Stream Encrypt(out string dataKey, Stream plaintextStream)
		{
			return Encrypt(out dataKey, plaintextStream, null);
		}

		public Stream Encrypt(out string dataKey, Stream plaintextStream, IDictionary<string, string> context)
		{
			byte[] keyBytes;
			Stream stream = Encrypt(out keyBytes, plaintextStream, context);
			dataKey = Convert.ToBase64String(keyBytes);
			return stream;
		}

		public string Encrypt(out string dataKey, string plaintext)
		{
			return Encrypt(out dataKey, plaintext, null);
		}

		public IEnumerable<string> Encrypt(out string dataKey, IEnumerable<string> plaintexts, IDictionary<string, string> context)
		{
			byte[] byteDataKey;
			IEnumerable<byte[]> encryptedPayloads = Encrypt(out byteDataKey, plaintexts.Select(_binaryEncoding.GetBytes), context);
			dataKey = EncodeKey(byteDataKey);
			return encryptedPayloads.Select(x => new EncryptedItem(_config, x).Encode()).ToList();
		}

		public IEnumerable<string> Encrypt(out string dataKey, IEnumerable<string> plaintexts)
		{
			return Encrypt(out dataKey, plaintexts, null);
		}

		public byte[] Decrypt(byte[] dataKey, byte[] ciphertextBlob, IDictionary<string, string> context)
		{
			return Decrypt(dataKey, new[] {ciphertextBlob}, context).Single();
		}

		public byte[] Decrypt(byte[] dataKey, byte[] ciphertextBlob)
		{
			return Decrypt(dataKey, ciphertextBlob, null);
		}

		public Stream Decrypt(byte[] dataKey, Stream ciphertextStream, IDictionary<string, string> context)
		{
			byte[] plaintextKey = _dataKeyProvider.DecryptKey(dataKey, context);

			var iv = new byte[IVBytes];
			if (! TryFillBuffer(ciphertextStream, iv))
			{
				throw new CryptographicException("not enough data in input stream");
			}

			ISymmetricAlgorithm algo = null;
			try
			{
				algo = _algorithmFactory.CreateAlgorithm(_config);
				algo.Key = plaintextKey;
				algo.IV = iv;

				ICryptoTransform decryptor = algo.CreateDecryptor();
				Stream cryptoStream = new CryptoStream(ciphertextStream, decryptor, CryptoStreamMode.Read);

				// when this stream is disposed, the algo and decryptor will be, too.
				return new StreamWithDisposables(cryptoStream, new IDisposable[] {algo, decryptor});
			}
			catch (Exception e)
			{
				// If we had trouble creating the stream, destroy the algorithm to prevent the key leaking.
				if (algo != null)
				{
					try
					{
						algo.Dispose();
					}
					catch (Exception disposalException)
					{
						throw new AggregateException(e, disposalException);
					}
				}
				throw;
			}
		}

		public Stream Decrypt(byte[] dataKey, Stream ciphertextStream)
		{
			return Decrypt(dataKey, ciphertextStream, null);
		}

		public IEnumerable<byte[]> Decrypt(byte[] dataKey, IEnumerable<byte[]> ciphertextBlobs, IDictionary<string, string> context)
		{
			return Decrypt(dataKey, ciphertextBlobs.Select(x => new EncryptedItem(_config, x)), context);
		}

		public Stream Decrypt(string dataKey, Stream ciphertextStream, IDictionary<string, string> context)
		{
			byte[] keyBytes = Convert.FromBase64String(dataKey);
			return Decrypt(keyBytes, ciphertextStream, context);
		}

		public Stream Decrypt(string dataKey, Stream ciphertextStream)
		{
			return Decrypt(dataKey, ciphertextStream, null);
		}

		public IEnumerable<byte[]> Decrypt(byte[] dataKey, IEnumerable<byte[]> ciphertextBlobs)
		{
			return Decrypt(dataKey, ciphertextBlobs, null);
		}

		public string Decrypt(string dataKey, string ciphertext, IDictionary<string, string> context)
		{
			return Decrypt(dataKey, new[] {ciphertext}, context).Single();
		}

		public string Decrypt(string dataKey, string ciphertext)
		{
			return Decrypt(dataKey, ciphertext, null);
		}

		public IEnumerable<string> Decrypt(string dataKey, IEnumerable<string> ciphertexts, IDictionary<string, string> context)
		{
			byte[] keyBytes = Convert.FromBase64String(dataKey);
			IEnumerable<EncryptedItem> decoded = ciphertexts.Select(EncryptedItem.Parse);
			IEnumerable<byte[]> decrypted = Decrypt(keyBytes, decoded, context);
			return decrypted.Select(_binaryEncoding.GetString);
		}

		public IEnumerable<string> Decrypt(string dataKey, IEnumerable<string> ciphertexts)
		{
			return Decrypt(dataKey, ciphertexts, null);
		}

		public byte[] Encrypt(out string dataKey, byte[] plaintextBlob, IDictionary<string, string> context)
		{
			byte[] keyBytes;
			byte[] result = Encrypt(out keyBytes, plaintextBlob, context);
			dataKey = EncodeKey(keyBytes);
			return result;
		}

		public byte[] Encrypt(out string dataKey, byte[] plaintextBlob)
		{
			return Encrypt(out dataKey, plaintextBlob, null);
		}

		public IEnumerable<byte[]> Encrypt(out string dataKey, IEnumerable<byte[]> plaintextBlobs, IDictionary<string, string> context)
		{
			byte[] keyBytes;
			IEnumerable<byte[]> result = Encrypt(out keyBytes, plaintextBlobs, context);
			dataKey = EncodeKey(keyBytes);
			return result;
		}

		public IEnumerable<byte[]> Encrypt(out string dataKey, IEnumerable<byte[]> plaintextBlobs)
		{
			return Encrypt(out dataKey, plaintextBlobs, null);
		}

		public byte[] Decrypt(string dataKey, byte[] ciphertextBlob, IDictionary<string, string> context)
		{
			return Decrypt(DecodeKey(dataKey), ciphertextBlob, context);
		}

		public byte[] Decrypt(string dataKey, byte[] ciphertextBlob)
		{
			return Decrypt(dataKey, ciphertextBlob, null);
		}

		public IEnumerable<byte[]> Decrypt(string dataKey, IEnumerable<byte[]> ciphertextBlobs, IDictionary<string, string> context)
		{
			return Decrypt(DecodeKey(dataKey), ciphertextBlobs, context);
		}

		public IEnumerable<byte[]> Decrypt(string dataKey, IEnumerable<byte[]> ciphertextBlobs)
		{
			return Decrypt(dataKey, ciphertextBlobs, null);
		}

		private static bool TryFillBuffer(Stream input, byte[] buffer)
		{
			int totalRead = 0;
			while (totalRead < buffer.Length)
			{
				int bytesRead = input.Read(buffer, totalRead, buffer.Length - totalRead);
				totalRead += bytesRead;
				if (bytesRead == 0)
				{
					return false; // eof
				}
			}
			return true;
		}

		private IEnumerable<byte[]> Decrypt(byte[] dataKey, IEnumerable<EncryptedItem> encrypted, IDictionary<string, string> context)
		{
			byte[] plaintextKey = _dataKeyProvider.DecryptKey(dataKey, context);

			var results = new List<byte[]>();
			foreach (EncryptedItem item in encrypted)
			{
				using (ISymmetricAlgorithm algo = _algorithmFactory.CreateAlgorithm(item))
				{
					algo.Key = plaintextKey;
					results.Add(Decrypt(algo, item.Payload));
				}
			}
			return results;
		}

		private static string EncodeKey(byte[] key)
		{
			return Convert.ToBase64String(key);
		}

		private static byte[] DecodeKey(string key)
		{
			return Convert.FromBase64String(key);
		}

		private static byte[] Encrypt(ISymmetricAlgorithm algorithm, byte[] plaintext)
		{
			using (var outputStream = new MemoryStream())
			{
				using (ICryptoTransform encryptor = algorithm.CreateEncryptor())
				{
					using (var cryptoStream = new CryptoStream(outputStream, encryptor, CryptoStreamMode.Write))
					{
						// write the IV to the top of the output stream
						outputStream.Write(algorithm.IV, 0, algorithm.IV.Length);
						// and then write the rest of the payload as ciphertext
						cryptoStream.Write(plaintext, 0, plaintext.Length);
						cryptoStream.FlushFinalBlock();
						cryptoStream.Flush();
						return outputStream.ToArray();
					}
				}
			}
		}

		private byte[] Decrypt(ISymmetricAlgorithm algo, byte[] ivAndCiphertext)
		{
			// The encrypted payload's first block is the IV, the rest is cipher text.
			byte[] iv, ciphertext;
			DecodeCiphertext(ivAndCiphertext, out iv, out ciphertext);
			algo.IV = iv;

			using (var inputStream = new MemoryStream(ciphertext))
			{
				using (ICryptoTransform decryptor = algo.CreateDecryptor())
				{
					using (var cryptoStream = new CryptoStream(inputStream, decryptor, CryptoStreamMode.Read))
					{
						using (var resultStream = new MemoryStream())
						{
							cryptoStream.CopyTo(resultStream);
							return resultStream.ToArray();
						}
					}
				}
			}
		}

		private static void DecodeCiphertext(byte[] ivAndCiphertext, out byte[] iv, out byte[] ciphertext)
		{
			if (ivAndCiphertext.Length < (IVBytes + BlockBytes))
			{
				throw new ArgumentException("The encrypted blob must contain at least one IV and one block.", "ivAndCiphertext");
			}
			iv = new byte[IVBytes];
			ciphertext = new byte[ivAndCiphertext.Length - IVBytes];

			Array.Copy(ivAndCiphertext, iv, IVBytes);
			Array.Copy(ivAndCiphertext, IVBytes, ciphertext, 0, ciphertext.Length);
		}
	}
}