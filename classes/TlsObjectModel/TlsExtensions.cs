using System.Collections.ObjectModel;

namespace TlsObjectModel
{

	public static class TlsExtensions
	{
		// Dictionary matching the known data types of fixed length with the number of bytes they use
		private static readonly ReadOnlyDictionary<Type, UInt32> TlsFixedObjectLengths = new(new Dictionary<Type, uint>()
		{
			{ typeof(CipherSuite), 2 },
			{ typeof(ContentType), 1 },
			{ typeof(ExtensionType), 4 },
			{ typeof(HandshakeType), 1 },
			{ typeof(ProtocolVersion), 2 },
			{ typeof(Random), 32 },
		});
		private static readonly ReadOnlyDictionary<Type, UInt32> TlsLengthFieldLengths = new(new Dictionary<Type, uint>() {
			{ typeof(Handshake), 3},
			{ typeof(TLSPlaintext), 2},
		});
		public static bool IsFixedLength(this Type type)
		{
			return TlsFixedObjectLengths.ContainsKey(type);
		}
		public static uint GetFixedLength(this Type type)
		{
			if (!type.IsFixedLength()) throw new ArgumentException();
			else return TlsFixedObjectLengths[type];
		}
		public static uint GetLengthFieldLength(this Type type)
		{
			if (type.IsFixedLength()) return 0;
			else if (TlsLengthFieldLengths.ContainsKey(type)) return TlsLengthFieldLengths[type];
			else throw new NotSupportedException();
		}
		public static ulong GetLength(this Type type, byte[] bytes)
		{
			if (type.IsFixedLength()) throw new ArgumentException();
			bytes = new ArraySegment<byte>(bytes, 0, (int)GetLengthFieldLength(type)).ToArray();
			return Utils.BytesToUInt64(bytes);
		}
		public static byte[] ToBytes(this Enum value)
		{
			uint length;
			if (value.GetType().IsFixedLength()) length = value.GetType().GetFixedLength();
			else throw new NotSupportedException();
			ulong valueNum = Convert.ToUInt64(value);
			return valueNum.ToBytes(length);
		}
		public static void FromBytes(this Enum value, byte[] bytes)
		{
			uint length;
			if (value.GetType().IsFixedLength()) length = value.GetType().GetFixedLength();
			else throw new NotSupportedException();
			if (bytes.Length != length || bytes.Length > 8) throw new NotSupportedException();
			ulong number = Utils.BytesToUInt64(bytes);
			value = (Enum)Enum.ToObject(value.GetType(), number);
		}
		public static byte[] ToBytes(this ulong value, ulong length)
		{
			byte[] rawBytes = BitConverter.GetBytes(value);
			if (BitConverter.IsLittleEndian) rawBytes = rawBytes.Reverse().ToArray();
			for (ulong i = 0; i < (ulong)rawBytes.Length - length; i++)
			{
				if (rawBytes[i] != 0) throw new OverflowException();
			}
			return new ArraySegment<byte>(rawBytes, (int)((ulong)rawBytes.Length - length), (int)length).ToArray();
		}
		public static byte[] Remove(this byte[] bytes, int i)
		{
			int length = bytes.Length;
			if (length < i) throw new ArgumentException();
			return new ArraySegment<byte>(bytes, i, length - i).ToArray();
		}
	}

}