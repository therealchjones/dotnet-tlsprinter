namespace TlsObjectModel
{
	/// <summary>
	/// The base object from which all <see cref="TlsObjectModel"/> classes are
	/// derived.
	/// </summary>
	public abstract class TlsObject
	{
		/// <summary>
		/// A <see cref="ByteArray"/> containing the data from which the
		/// individual members of this <see cref="TlsObject"/> are read.
		/// </summary>
		/// <remarks>
		/// <para><see cref="BackingBytes"/> stores the raw data used to create
		/// the properties and fields of the <see cref="TlsObject"/>. To get a
		/// copy of this data for manipulation, use <see
		/// cref="GetRawData()"/>.</para>
		protected byte[]? BackingBytes { get; set; }
		/// <summary>
		/// Creates a byte array representation of this <see cref="TlsObject"/>
		/// </summary>
		/// <remarks>If this <see cref="TlsObject"/> was created by reading a
		/// series of <see cref="Byte"/>s, <see cref="ToBytes()"/> will not
		/// necessarily return an identical series of bytes. To obtain a copy of
		/// the original byte array from that scenario, use <see
		/// cref="GetRawData()"/>.
		/// <returns>A byte array formatted per TLS requirements representing
		/// this <see cref="TlsObject"/></returns>
		public abstract byte[] ToBytes();
		/// <summary>
		/// Sets the appropriate properties and fields of this <see
		/// cref="TlsObject"/> using the data from a given byte array.
		/// </summary>
		/// <remarks>
		/// Using a provided byte array formatted as specified for TLS, <see
		/// cref="FromBytes"/> sets the properties of this <see
		/// cref="TlsObject"/> and stores the given byte array. (This can be
		/// retrieved using <see cref="GetRawData()"/>.) If this <see
		/// cref="TlsObject"/> already has properties that were specified in
		/// another manner, <see cref="FromBytes"/> may overwrite them. If <see
		/// paramref="bytes"/> does not contain all data needed for this <see
		/// cref="TlsObject"/>, more can be added via <see
		/// cref="AddBytes"/>.</remarks>
		/// <param name="bytes">Byte array from which to read data</param>
		public abstract void FromBytes(byte[] bytes);
		/// <summary>
		/// Adds data to set the appropriate properties and fields of this <see
		/// cref="TlsObject"/>
		/// </summary>
		/// <remarks>Using the provided byte array, <see cref="AddBytes"/> reads
		/// properties of this <see cref="TlsObject"/> and sets them
		/// accordingly. If this <see cref="TlsObject"/> already has properties
		/// that were defined in some other manner, <see cref="AddBytes"/> may
		/// overwrite them. If other data was already added via <see
		/// cref="FromBytes"/> or previous calls to <see cref="AddBytes"/>, <see
		/// paramref="bytes"/> is appended to this as if a continuation of data
		/// from a stream.</remarks>
		/// <param name="bytes">Byte array from which to read data.</param>
		public abstract void AddBytes(byte[] bytes);
		/// <summary>
		/// Adds data to set the appropriate properties and fields of this <see
		/// cref="TlsObject"/>
		/// </summary>
		/// <remarks>Using the provided byte stream, <see cref="AddBytes"/> reads
		/// properties of this <see cref="TlsObject"/> and sets them
		/// accordingly. If this <see cref="TlsObject"/> already has properties
		/// that were defined in some other manner, <see cref="AddBytes"/> may
		/// overwrite them. If other data was already added via <see
		/// cref="FromBytes"/> or previous calls to <see cref="AddBytes"/>, <see
		/// paramref="bytes"/> is appended to this as if a continuation of data
		/// from a stream.</remarks>
		/// <param name="bytes">Byte collection from which to read data.</param>
		public void AddBytes(IEnumerable<byte> bytes)
		{
			AddBytes(bytes.ToArray<byte>());
		}
		/// <summary>
		/// Determines whether this <see cref="TlsObject"/> was created from a
		/// collection of bytes
		/// </summary>
		/// <returns><c>true</c> if this <see cref="TlsObject"/> includes
		/// initial backing data that can be obtained, <c>false</c>
		/// otherwise</returns>
		public bool HasRawData()
		{
			return BackingBytes is not null;
		}
		/// <summary>
		/// Provides a copy of the byte array from which this <see
		/// cref="TlsObject"/>'s members are created.
		/// </summary>
		/// <remarks>This method provides a copy of the raw data used to create
		/// this <see cref="TlsObject"/>. If the object's properties were not
		/// initially read from a TLS data source, such as when created with a
		/// <c>new TlsObject()</c> directive followed by individual settings of
		/// the properties, <see cref="GetRawData()"/> throws an <see
		/// cref="InvalidOperationException"/>. To obtain a byte array
		/// representation of the <see cref="TlsObject"/> regardless of how it
		/// was created, use <see cref="ToBytes()"/>.</remarks>
		/// <returns>A copy of the data from which this <see
		/// cref="TlsObject"/>'s properties were read.</returns>
		/// <exception cref="InvalidOperationException">If this <see
		/// cref="TlsObject"/> was not created from a <see cref="ByteArray"/> or
		/// <see cref="byte"/> stream.</exception>
		public byte[] GetRawData()
		{
			if (BackingBytes is null) throw new InvalidOperationException();
			return BackingBytes[0..^0];
		}
	}
}