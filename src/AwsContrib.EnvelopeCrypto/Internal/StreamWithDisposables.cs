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
using System.Runtime.Remoting;
using System.Threading;
using System.Threading.Tasks;

namespace AwsContrib.EnvelopeCrypto.Internal
{
	/// <summary>
	///     A stream wrapper that triggers the disposal of other objects when it is disposed.
	///     This is used to dispose of the SymmetricAlgorithm and ICryptoTransform when the
	///     related CrytoStream is disposed.
	/// </summary>
	internal class StreamWithDisposables : Stream
	{
		private readonly List<IDisposable> _disposables;
		private readonly Stream _inner;
		private bool _isDisposed;

		public StreamWithDisposables(Stream inner, IEnumerable<IDisposable> disposables)
		{
			_inner = inner;
			_disposables = new List<IDisposable>(disposables);
		}

		protected override void Dispose(bool disposing)
		{
			if (_isDisposed)
			{
				throw new ObjectDisposedException("the instance has already been disposed");
			}
			_isDisposed = true;

			var caught = new List<Exception>();
			foreach (IDisposable disposable in _disposables)
			{
				try
				{
					disposable.Dispose();
				}
				catch (Exception e)
				{
					caught.Add(e);
				}
			}

			try
			{
				base.Dispose(disposing);
			}
			catch (Exception e)
			{
				caught.Add(e);
			}

			if (caught.Count > 0)
			{
				throw new AggregateException(caught);
			}
		}

		#region Generated Code

		public override bool CanRead
		{
			get { return _inner.CanRead; }
		}

		public override bool CanSeek
		{
			get { return _inner.CanSeek; }
		}

		public override bool CanTimeout
		{
			get { return _inner.CanTimeout; }
		}

		public override bool CanWrite
		{
			get { return _inner.CanWrite; }
		}

		public override long Length
		{
			get { return _inner.Length; }
		}

		public override long Position
		{
			get { return _inner.Position; }
			set { _inner.Position = value; }
		}

		public override int ReadTimeout
		{
			get { return _inner.ReadTimeout; }
			set { _inner.ReadTimeout = value; }
		}

		public override int WriteTimeout
		{
			get { return _inner.WriteTimeout; }
			set { _inner.WriteTimeout = value; }
		}

		public override ObjRef CreateObjRef(Type requestedType)
		{
			return _inner.CreateObjRef(requestedType);
		}

		public override Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken)
		{
			return _inner.CopyToAsync(destination, bufferSize, cancellationToken);
		}

		public override void Close()
		{
			_inner.Close();
		}

		public override void Flush()
		{
			_inner.Flush();
		}

		public override Task FlushAsync(CancellationToken cancellationToken)
		{
			return _inner.FlushAsync(cancellationToken);
		}

		public override IAsyncResult BeginRead(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
		{
			return _inner.BeginRead(buffer, offset, count, callback, state);
		}

		public override int EndRead(IAsyncResult asyncResult)
		{
			return _inner.EndRead(asyncResult);
		}

		public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
		{
			return _inner.ReadAsync(buffer, offset, count, cancellationToken);
		}

		public override IAsyncResult BeginWrite(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
		{
			return _inner.BeginWrite(buffer, offset, count, callback, state);
		}

		public override void EndWrite(IAsyncResult asyncResult)
		{
			_inner.EndWrite(asyncResult);
		}

		public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
		{
			return _inner.WriteAsync(buffer, offset, count, cancellationToken);
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			return _inner.Seek(offset, origin);
		}

		public override void SetLength(long value)
		{
			_inner.SetLength(value);
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			return _inner.Read(buffer, offset, count);
		}

		public override int ReadByte()
		{
			return _inner.ReadByte();
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			_inner.Write(buffer, offset, count);
		}

		public override void WriteByte(byte value)
		{
			_inner.WriteByte(value);
		}

		#endregion
	}
}