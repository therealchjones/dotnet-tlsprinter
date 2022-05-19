namespace TlsObjectModel
{
	public class ClientHello : HandshakeContent
	{
		ProtocolVersion legacy_version = new(new byte[] { 3, 3 });
		public byte[]? Random;
		public byte[]? legacy_session_id;
		public List<CipherSuite> cipher_suites = new();
		public byte[]? legacy_compression_methods;
		public List<Extension>? Extensions;
		public ClientHello()
		{

		}
		public ClientHello(byte[] bytes)
		{
			FromBytes(bytes);
		}
		public override void FromBytes(byte[] bytes)
		{
			if (BackingBytes is not null && BackingBytes.Length > 0)
			{
				throw new InvalidOperationException();
			}
			AddBytes(bytes);
		}
		public override void AddBytes(byte[] bytes)
		{
			ArgumentNullException.ThrowIfNull(bytes);
			if (BackingBytes is null) BackingBytes = new byte[0];
			BackingBytes = BackingBytes.Concat(bytes).ToArray();
			if (BackingBytes.Length >= 2) legacy_version = new(BackingBytes[0..2]);
			if (BackingBytes.Length >= 34) Random = BackingBytes[2..34];
			byte sessionIdLength = 0;
			if (BackingBytes.Length >= 35) sessionIdLength = BackingBytes[34];
			if (BackingBytes.Length >= 35 + sessionIdLength)
			{
				if (sessionIdLength == 0) legacy_session_id = new byte[0];
				else legacy_session_id = BackingBytes[35..(35 + sessionIdLength)];
			}
			ushort cipherSuiteListLength = 0;
			if (BackingBytes.Length >= 35 + sessionIdLength + 2)
			{
				cipherSuiteListLength = (ushort)TlsUtils.BytesToUInt64(BackingBytes[(35 + sessionIdLength)..(35 + sessionIdLength + 2)]);
			}
			if (BackingBytes.LongLength >= 35 + sessionIdLength + 2 + cipherSuiteListLength)
			{
				if (cipherSuiteListLength == 0) cipher_suites = new();
				else
				{
					if (cipherSuiteListLength % 2 != 0) throw new InvalidDataException();
					for (int i = 0; i < cipherSuiteListLength / 2; i++)
					{
						var index = 35 + sessionIdLength + 2 + (2 * i);
						cipher_suites.Add(new CipherSuite(BackingBytes[index..(index + 2)]));
					}
				}
			}
			if (BackingBytes.LongLength >= 35 + sessionIdLength + 2 + cipherSuiteListLength + 2)
			{
				var index = 35 + sessionIdLength + 2 + cipherSuiteListLength;
				byte compressionMessageListLength = BackingBytes[index];
				if (compressionMessageListLength != 1) throw new NotSupportedException();
				legacy_compression_methods = BackingBytes[(index + 1)..(index + 1 + compressionMessageListLength)];
				if (legacy_compression_methods[0] != 0) throw new NotSupportedException();
			}
			ulong extensionsLength = 0;
			var arrayLength = 35 + sessionIdLength + 2 + cipherSuiteListLength + 2;

			if (BackingBytes.LongLength >= arrayLength + 1)
			{
				extensionsLength = TlsUtils.BytesToUInt64(BackingBytes[(arrayLength)..(arrayLength + 2)]);
			}
			arrayLength = arrayLength + 2 + (int)extensionsLength;
			if (BackingBytes.LongLength >= arrayLength)
			{
				if (Extensions is null) Extensions = new();
				if (extensionsLength > 0)
				{
					ulong totalLength = 0;
					ExtensionType extensionType;
					ushort thisLength;
					var index = (ulong)arrayLength - extensionsLength;
					while (totalLength <= extensionsLength - 4)
					{
						extensionType = (ExtensionType)TlsUtils.BytesToUInt64(BackingBytes[(int)(index + totalLength)..(int)(index + totalLength + 2)]);
						thisLength = (ushort)TlsUtils.BytesToUInt64(BackingBytes[(int)(index + totalLength + 2)..(int)(index + totalLength + 4)]);
						byte[] extensionBytes = BackingBytes[(int)(index + totalLength)..(int)(index + totalLength + 4 + thisLength)];
						Extension newExtension;
						switch (extensionType)
						{
							//case ExtensionType.server_name:
							//newExtension = new ServerNameExtension(extensionBytes);
							//break;
							default:
								newExtension = new UnknownExtension(extensionBytes);
								break;
						}
						Extensions.Add(newExtension);
						totalLength = totalLength + thisLength + 4;
					}
				}
			}
		}
		public override byte[] ToBytes()
		{
			if (Random is null || legacy_session_id is null || legacy_compression_methods is null || Extensions is null)
			{
				if (BackingBytes is null || BackingBytes.Length == 0) throw new InvalidOperationException();
				else return BackingBytes;
			}
			byte[] cipherSuitesArray = new byte[0];
			foreach (CipherSuite cipher in cipher_suites)
			{
				cipherSuitesArray = cipherSuitesArray.Concat(cipher.ToBytes()).ToArray();
			}
			if (legacy_compression_methods is null || legacy_compression_methods.Length == 0)
				throw new InvalidOperationException();
			if (legacy_compression_methods.Length != 1) throw new NotSupportedException();
			byte[] extensionsArray = new byte[0];
			foreach (Extension extension in Extensions)
			{
				extensionsArray = extensionsArray.Concat(extension.ToBytes()).ToArray();
			}
			return legacy_version.ToBytes()
					.Concat(Random)
					.Concat(((ulong)legacy_session_id.LongLength).ToBytes(1))
					.Concat(legacy_session_id)
					.Concat(((ulong)cipherSuitesArray.LongLength).ToBytes(2))
					.Concat(cipherSuitesArray)
					.Concat(new byte[2] { 1, 0 })
					.Concat(((ulong)extensionsArray.LongLength).ToBytes(2))
					.Concat(extensionsArray)
					.ToArray();
		}
	}
}