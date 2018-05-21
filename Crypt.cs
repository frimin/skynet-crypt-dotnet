namespace Skynet
{
    using System;
    using System.Collections;
    using System.Text;
    using System.Security;

    public class Crypt {
		private static readonly int SMALL_CHUNK = 256;

		/* the eight DES S-boxes */
	
		private static readonly UInt32 [] SB1 = new UInt32 [64] {
			0x01010400, 0x00000000, 0x00010000, 0x01010404,
			0x01010004, 0x00010404, 0x00000004, 0x00010000,
			0x00000400, 0x01010400, 0x01010404, 0x00000400,
			0x01000404, 0x01010004, 0x01000000, 0x00000004,
			0x00000404, 0x01000400, 0x01000400, 0x00010400,
			0x00010400, 0x01010000, 0x01010000, 0x01000404,
			0x00010004, 0x01000004, 0x01000004, 0x00010004,
			0x00000000, 0x00000404, 0x00010404, 0x01000000,
			0x00010000, 0x01010404, 0x00000004, 0x01010000,
			0x01010400, 0x01000000, 0x01000000, 0x00000400,
			0x01010004, 0x00010000, 0x00010400, 0x01000004,
			0x00000400, 0x00000004, 0x01000404, 0x00010404,
			0x01010404, 0x00010004, 0x01010000, 0x01000404,
			0x01000004, 0x00000404, 0x00010404, 0x01010400,
			0x00000404, 0x01000400, 0x01000400, 0x00000000,
			0x00010004, 0x00010400, 0x00000000, 0x01010004
		};

		private static readonly UInt32 [] SB2 = new UInt32[64] {
			0x80108020, 0x80008000, 0x00008000, 0x00108020,
			0x00100000, 0x00000020, 0x80100020, 0x80008020,
			0x80000020, 0x80108020, 0x80108000, 0x80000000,
			0x80008000, 0x00100000, 0x00000020, 0x80100020,
			0x00108000, 0x00100020, 0x80008020, 0x00000000,
			0x80000000, 0x00008000, 0x00108020, 0x80100000,
			0x00100020, 0x80000020, 0x00000000, 0x00108000,
			0x00008020, 0x80108000, 0x80100000, 0x00008020,
			0x00000000, 0x00108020, 0x80100020, 0x00100000,
			0x80008020, 0x80100000, 0x80108000, 0x00008000,
			0x80100000, 0x80008000, 0x00000020, 0x80108020,
			0x00108020, 0x00000020, 0x00008000, 0x80000000,
			0x00008020, 0x80108000, 0x00100000, 0x80000020,
			0x00100020, 0x80008020, 0x80000020, 0x00100020,
			0x00108000, 0x00000000, 0x80008000, 0x00008020,
			0x80000000, 0x80100020, 0x80108020, 0x00108000
		};

		private static readonly UInt32 [] SB3 = new UInt32[64] {
			0x00000208, 0x08020200, 0x00000000, 0x08020008,
			0x08000200, 0x00000000, 0x00020208, 0x08000200,
			0x00020008, 0x08000008, 0x08000008, 0x00020000,
			0x08020208, 0x00020008, 0x08020000, 0x00000208,
			0x08000000, 0x00000008, 0x08020200, 0x00000200,
			0x00020200, 0x08020000, 0x08020008, 0x00020208,
			0x08000208, 0x00020200, 0x00020000, 0x08000208,
			0x00000008, 0x08020208, 0x00000200, 0x08000000,
			0x08020200, 0x08000000, 0x00020008, 0x00000208,
			0x00020000, 0x08020200, 0x08000200, 0x00000000,
			0x00000200, 0x00020008, 0x08020208, 0x08000200,
			0x08000008, 0x00000200, 0x00000000, 0x08020008,
			0x08000208, 0x00020000, 0x08000000, 0x08020208,
			0x00000008, 0x00020208, 0x00020200, 0x08000008,
			0x08020000, 0x08000208, 0x00000208, 0x08020000,
			0x00020208, 0x00000008, 0x08020008, 0x00020200
		};

		private static readonly UInt32 [] SB4 = new UInt32[64] {
			0x00802001, 0x00002081, 0x00002081, 0x00000080,
			0x00802080, 0x00800081, 0x00800001, 0x00002001,
			0x00000000, 0x00802000, 0x00802000, 0x00802081,
			0x00000081, 0x00000000, 0x00800080, 0x00800001,
			0x00000001, 0x00002000, 0x00800000, 0x00802001,
			0x00000080, 0x00800000, 0x00002001, 0x00002080,
			0x00800081, 0x00000001, 0x00002080, 0x00800080,
			0x00002000, 0x00802080, 0x00802081, 0x00000081,
			0x00800080, 0x00800001, 0x00802000, 0x00802081,
			0x00000081, 0x00000000, 0x00000000, 0x00802000,
			0x00002080, 0x00800080, 0x00800081, 0x00000001,
			0x00802001, 0x00002081, 0x00002081, 0x00000080,
			0x00802081, 0x00000081, 0x00000001, 0x00002000,
			0x00800001, 0x00002001, 0x00802080, 0x00800081,
			0x00002001, 0x00002080, 0x00800000, 0x00802001,
			0x00000080, 0x00800000, 0x00002000, 0x00802080
		};

		private static readonly UInt32 [] SB5 = new UInt32[64] {
			0x00000100, 0x02080100, 0x02080000, 0x42000100,
			0x00080000, 0x00000100, 0x40000000, 0x02080000,
			0x40080100, 0x00080000, 0x02000100, 0x40080100,
			0x42000100, 0x42080000, 0x00080100, 0x40000000,
			0x02000000, 0x40080000, 0x40080000, 0x00000000,
			0x40000100, 0x42080100, 0x42080100, 0x02000100,
			0x42080000, 0x40000100, 0x00000000, 0x42000000,
			0x02080100, 0x02000000, 0x42000000, 0x00080100,
			0x00080000, 0x42000100, 0x00000100, 0x02000000,
			0x40000000, 0x02080000, 0x42000100, 0x40080100,
			0x02000100, 0x40000000, 0x42080000, 0x02080100,
			0x40080100, 0x00000100, 0x02000000, 0x42080000,
			0x42080100, 0x00080100, 0x42000000, 0x42080100,
			0x02080000, 0x00000000, 0x40080000, 0x42000000,
			0x00080100, 0x02000100, 0x40000100, 0x00080000,
			0x00000000, 0x40080000, 0x02080100, 0x40000100
		};

		private static readonly UInt32 [] SB6 = new UInt32[64] {
			0x20000010, 0x20400000, 0x00004000, 0x20404010,
			0x20400000, 0x00000010, 0x20404010, 0x00400000,
			0x20004000, 0x00404010, 0x00400000, 0x20000010,
			0x00400010, 0x20004000, 0x20000000, 0x00004010,
			0x00000000, 0x00400010, 0x20004010, 0x00004000,
			0x00404000, 0x20004010, 0x00000010, 0x20400010,
			0x20400010, 0x00000000, 0x00404010, 0x20404000,
			0x00004010, 0x00404000, 0x20404000, 0x20000000,
			0x20004000, 0x00000010, 0x20400010, 0x00404000,
			0x20404010, 0x00400000, 0x00004010, 0x20000010,
			0x00400000, 0x20004000, 0x20000000, 0x00004010,
			0x20000010, 0x20404010, 0x00404000, 0x20400000,
			0x00404010, 0x20404000, 0x00000000, 0x20400010,
			0x00000010, 0x00004000, 0x20400000, 0x00404010,
			0x00004000, 0x00400010, 0x20004010, 0x00000000,
			0x20404000, 0x20000000, 0x00400010, 0x20004010
		};

		private static readonly UInt32 [] SB7 = new UInt32[64] {
			0x00200000, 0x04200002, 0x04000802, 0x00000000,
			0x00000800, 0x04000802, 0x00200802, 0x04200800,
			0x04200802, 0x00200000, 0x00000000, 0x04000002,
			0x00000002, 0x04000000, 0x04200002, 0x00000802,
			0x04000800, 0x00200802, 0x00200002, 0x04000800,
			0x04000002, 0x04200000, 0x04200800, 0x00200002,
			0x04200000, 0x00000800, 0x00000802, 0x04200802,
			0x00200800, 0x00000002, 0x04000000, 0x00200800,
			0x04000000, 0x00200800, 0x00200000, 0x04000802,
			0x04000802, 0x04200002, 0x04200002, 0x00000002,
			0x00200002, 0x04000000, 0x04000800, 0x00200000,
			0x04200800, 0x00000802, 0x00200802, 0x04200800,
			0x00000802, 0x04000002, 0x04200802, 0x04200000,
			0x00200800, 0x00000000, 0x00000002, 0x04200802,
			0x00000000, 0x00200802, 0x04200000, 0x00000800,
			0x04000002, 0x04000800, 0x00000800, 0x00200002
		};

		private static readonly UInt32 [] SB8 = new UInt32[64] {
			0x10001040, 0x00001000, 0x00040000, 0x10041040,
			0x10000000, 0x10001040, 0x00000040, 0x10000000,
			0x00040040, 0x10040000, 0x10041040, 0x00041000,
			0x10041000, 0x00041040, 0x00001000, 0x00000040,
			0x10040000, 0x10000040, 0x10001000, 0x00001040,
			0x00041000, 0x00040040, 0x10040040, 0x10041000,
			0x00001040, 0x00000000, 0x00000000, 0x10040040,
			0x10000040, 0x10001000, 0x00041040, 0x00040000,
			0x00041040, 0x00040000, 0x10041000, 0x00001000,
			0x00000040, 0x10040040, 0x00001000, 0x00041040,
			0x10001000, 0x00000040, 0x10000040, 0x10040000,
			0x10040040, 0x10000000, 0x00040000, 0x10001040,
			0x00000000, 0x10041040, 0x00040040, 0x10000040,
			0x10040000, 0x10001000, 0x10001040, 0x00000000,
			0x10041040, 0x00041000, 0x00041000, 0x00001040,
			0x00001040, 0x00040040, 0x10000000, 0x10041000
		};

		/* PC1: left and right halves bit-swap */

		private static readonly UInt32 [] LHs = new UInt32[16] {
			0x00000000, 0x00000001, 0x00000100, 0x00000101,
			0x00010000, 0x00010001, 0x00010100, 0x00010101,
			0x01000000, 0x01000001, 0x01000100, 0x01000101,
			0x01010000, 0x01010001, 0x01010100, 0x01010101
		};

		private static readonly UInt32 [] RHs = new UInt32[16] {
			0x00000000, 0x01000000, 0x00010000, 0x01010000,
			0x00000100, 0x01000100, 0x00010100, 0x01010100,
			0x00000001, 0x01000001, 0x00010001, 0x01010001,
			0x00000101, 0x01000101, 0x00010101, 0x01010101,
		};

		private static UInt32 GET_UINT32(byte[] binary, int index)
		{
			return ( (UInt32) (binary)[(index)	] << 24 )
				 | ( (UInt32) (binary)[(index) + 1] << 16 )
				 | ( (UInt32) (binary)[(index) + 2] <<  8 )
				 | ( (UInt32) (binary)[(index) + 3]	    );
		}

		private static void PUT_UINT32(UInt32 number, byte[] binary, int index)
		{
			(binary)[(index)	] = (byte) ( (number) >> 24 );
			(binary)[(index) + 1] = (byte) ( (number) >> 16 );
			(binary)[(index) + 2] = (byte) ( (number) >>  8 );
			(binary)[(index) + 3] = (byte) ( (number)	   );
		}

		private static void DES_IP(ref UInt32 X, ref UInt32 Y, ref UInt32 T)
		{
			T = ((X >>  4) ^ Y) & 0x0F0F0F0F; Y ^= T; X ^= (T <<  4);
			T = ((X >> 16) ^ Y) & 0x0000FFFF; Y ^= T; X ^= (T << 16);
			T = ((Y >>  2) ^ X) & 0x33333333; X ^= T; Y ^= (T <<  2);
			T = ((Y >>  8) ^ X) & 0x00FF00FF; X ^= T; Y ^= (T <<  8);
			Y = ((Y << 1) | (Y >> 31)) & 0xFFFFFFFF;
			T = (X ^ Y) & 0xAAAAAAAA; Y ^= T; X ^= T;
			X = ((X << 1) | (X >> 31)) & 0xFFFFFFFF;
		}

		private static void DES_FP(ref UInt32 X, ref UInt32 Y, ref UInt32 T)
		{
			X = ((X << 31) | (X >> 1)) & 0xFFFFFFFF;
			T = (X ^ Y) & 0xAAAAAAAA; X ^= T; Y ^= T;
			Y = ((Y << 31) | (Y >> 1)) & 0xFFFFFFFF;
			T = ((Y >>  8) ^ X) & 0x00FF00FF; X ^= T; Y ^= (T <<  8);
			T = ((Y >>  2) ^ X) & 0x33333333; X ^= T; Y ^= (T <<  2);
			T = ((X >> 16) ^ Y) & 0x0000FFFF; Y ^= T; X ^= (T << 16);
			T = ((X >>  4) ^ Y) & 0x0F0F0F0F; Y ^= T; X ^= (T <<  4);
		}

		private static void DES_ROUND(ref UInt32 X, ref UInt32 Y, ref UInt32 T, UInt32 [] SK, ref int SK_POS)
		{					
			T = SK[SK_POS] ^ X;
			SK_POS ++;
			Y ^= SB8[ (T	  ) & 0x3F ] ^
				 SB6[ (T >>  8) & 0x3F ] ^
				 SB4[ (T >> 16) & 0x3F ] ^
				 SB2[ (T >> 24) & 0x3F ];

			T = SK[SK_POS] ^ ((X << 28) | (X >> 4));
			SK_POS ++;
			Y ^= SB7[ (T	  ) & 0x3F ] ^
				 SB5[ (T >>  8) & 0x3F ] ^
				 SB3[ (T >> 16) & 0x3F ] ^
				 SB1[ (T >> 24) & 0x3F ];
		}

		/* DES key schedule */

		static void des_main_ks(UInt32 [] SK, byte [] key) {
			int i;

			UInt32 X, Y, T;

			X = GET_UINT32(key, 0);
			Y = GET_UINT32(key, 4);

			/* Permuted Choice 1 */

			T =  ((Y >>  4) ^ X) & 0x0F0F0F0F;  X ^= T; Y ^= (T <<  4);
			T =  ((Y	  ) ^ X) & 0x10101010;  X ^= T; Y ^= (T	  );

			X =   (LHs[ (X	  ) & 0xF] << 3) | (LHs[ (X >>  8) & 0xF ] << 2)
				| (LHs[ (X >> 16) & 0xF] << 1) | (LHs[ (X >> 24) & 0xF ]	 )
				| (LHs[ (X >>  5) & 0xF] << 7) | (LHs[ (X >> 13) & 0xF ] << 6)
				| (LHs[ (X >> 21) & 0xF] << 5) | (LHs[ (X >> 29) & 0xF ] << 4);

			Y =   (RHs[ (Y >>  1) & 0xF] << 3) | (RHs[ (Y >>  9) & 0xF ] << 2)
				| (RHs[ (Y >> 17) & 0xF] << 1) | (RHs[ (Y >> 25) & 0xF ]	 )
				| (RHs[ (Y >>  4) & 0xF] << 7) | (RHs[ (Y >> 12) & 0xF ] << 6)
				| (RHs[ (Y >> 20) & 0xF] << 5) | (RHs[ (Y >> 28) & 0xF ] << 4);

			X &= 0x0FFFFFFF;
			Y &= 0x0FFFFFFF;

			/* calculate subkeys */

			int SK_POS = 0;

			for( i = 0; i < 16; i++ )
			{
				if( i < 2 || i == 8 || i == 15 )
				{
					X = ((X <<  1) | (X >> 27)) & 0x0FFFFFFF;
					Y = ((Y <<  1) | (Y >> 27)) & 0x0FFFFFFF;
				}
				else
				{
					X = ((X <<  2) | (X >> 26)) & 0x0FFFFFFF;
					Y = ((Y <<  2) | (Y >> 26)) & 0x0FFFFFFF;
				}

				SK[SK_POS] =   ((X <<  4) & 0x24000000) | ((X << 28) & 0x10000000)
						| ((X << 14) & 0x08000000) | ((X << 18) & 0x02080000)
						| ((X <<  6) & 0x01000000) | ((X <<  9) & 0x00200000)
						| ((X >>  1) & 0x00100000) | ((X << 10) & 0x00040000)
						| ((X <<  2) & 0x00020000) | ((X >> 10) & 0x00010000)
						| ((Y >> 13) & 0x00002000) | ((Y >>  4) & 0x00001000)
						| ((Y <<  6) & 0x00000800) | ((Y >>  1) & 0x00000400)
						| ((Y >> 14) & 0x00000200) | ((Y	  ) & 0x00000100)
						| ((Y >>  5) & 0x00000020) | ((Y >> 10) & 0x00000010)
						| ((Y >>  3) & 0x00000008) | ((Y >> 18) & 0x00000004)
						| ((Y >> 26) & 0x00000002) | ((Y >> 24) & 0x00000001);
				SK_POS++;

				SK[SK_POS] =   ((X << 15) & 0x20000000) | ((X << 17) & 0x10000000)
						| ((X << 10) & 0x08000000) | ((X << 22) & 0x04000000)
						| ((X >>  2) & 0x02000000) | ((X <<  1) & 0x01000000)
						| ((X << 16) & 0x00200000) | ((X << 11) & 0x00100000)
						| ((X <<  3) & 0x00080000) | ((X >>  6) & 0x00040000)
						| ((X << 15) & 0x00020000) | ((X >>  4) & 0x00010000)
						| ((Y >>  2) & 0x00002000) | ((Y <<  8) & 0x00001000)
						| ((Y >> 14) & 0x00000808) | ((Y >>  9) & 0x00000400)
						| ((Y	  ) & 0x00000200) | ((Y <<  7) & 0x00000100)
						| ((Y >>  7) & 0x00000020) | ((Y >>  3) & 0x00000011)
						| ((Y <<  2) & 0x00000004) | ((Y >> 21) & 0x00000002);
				SK_POS++;
			}
		}

		/* DES 64-bit block encryption/decryption */

		static void des_crypt(UInt32 [] SK, Byte [] input, int inputIndex, Byte [] output, int outputIndex) {
			UInt32 X, Y, T = 0;

			X = GET_UINT32(input, inputIndex + 0);
			Y = GET_UINT32(input, inputIndex + 4);

			DES_IP(ref X, ref Y, ref T);

			int SK_POS = 0;

			DES_ROUND(ref Y, ref X, ref T, SK, ref SK_POS); DES_ROUND(ref X, ref Y, ref T, SK, ref SK_POS);
			DES_ROUND(ref Y, ref X, ref T, SK, ref SK_POS); DES_ROUND(ref X, ref Y, ref T, SK, ref SK_POS);
			DES_ROUND(ref Y, ref X, ref T, SK, ref SK_POS); DES_ROUND(ref X, ref Y, ref T, SK, ref SK_POS);
			DES_ROUND(ref Y, ref X, ref T, SK, ref SK_POS); DES_ROUND(ref X, ref Y, ref T, SK, ref SK_POS);
			DES_ROUND(ref Y, ref X, ref T, SK, ref SK_POS); DES_ROUND(ref X, ref Y, ref T, SK, ref SK_POS);
			DES_ROUND(ref Y, ref X, ref T, SK, ref SK_POS); DES_ROUND(ref X, ref Y, ref T, SK, ref SK_POS);
			DES_ROUND(ref Y, ref X, ref T, SK, ref SK_POS); DES_ROUND(ref X, ref Y, ref T, SK, ref SK_POS);
			DES_ROUND(ref Y, ref X, ref T, SK, ref SK_POS); DES_ROUND(ref X, ref Y, ref T, SK, ref SK_POS);

			DES_FP(ref Y, ref X, ref T);

			PUT_UINT32(Y, output, outputIndex + 0);
			PUT_UINT32(X, output, outputIndex + 4);
		}

		private static System.Random random;

		private static long GetTimeStamp()
		{
			TimeSpan ts = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0);
			return Convert.ToInt64(ts.TotalSeconds * 1000);
		}

		private static int RandomNum() {
			if (random == null) {
				random = new System.Random((int)GetTimeStamp());
			}
			return random.Next();
		}

		public static byte [] RandomKey() {
			byte [] tmp = new byte[8];
			int i;
			byte x = 0;
			for (i=0;i <8;i++) {
				tmp[i] = (byte)(RandomNum() & 0xff);
				x ^= tmp[i];
			}
			if (x==0) {
				tmp[0] |= 1;	// avoid 0
			}
			return tmp;
		}

		private static void des_key(UInt32 [] SK, byte [] key) {
			if (key.Length != 8) {
				throw new SystemException(string.Format("Invalid key size {0}, need 8 bytes", key.Length));
			}
			des_main_ks(SK, key);
		}

		private static byte [] tail = new byte[8];

		public static byte [] DesEncode(byte [] key, byte [] text) {
			UInt32 [] SK = new UInt32[32];

			des_key(SK, key);
			
			int textsz = text.Length;
			int chunksz = (textsz + 8) & ~7;

			byte [] buffer = new byte[chunksz];

			int i;
			for (i=0;i<(int)textsz-7;i+=8) {
				des_crypt(SK, text, i, buffer, i);
			}
			int bytes = textsz - i;

			int j;
			for (j=0;j<8;j++) {
				if (j < bytes) {
					tail[j] = text[i+j];
				} else if (j==bytes) {
					tail[j] = 0x80;
				} else {
					tail[j] = 0;
				}
			}
			
			des_crypt(SK, tail, 0, buffer, i);

			return buffer;
		}

		public static byte [] DesDecode(byte [] key, byte [] text) {
			byte [] buffer = new byte[text.Length];
			int len = DesDecode(key, text, buffer);
			byte [] ret = new byte[len];
			Array.Copy(buffer, ret, len);
			return ret;
		}

		public static int DesDecode(byte [] key, byte [] text, byte [] output) {
			UInt32 [] ESK = new UInt32[32];

			des_key(ESK, key);

			UInt32 [] SK = new UInt32[32];

			int i;
			for( i = 0; i < 32; i += 2 ) {
				SK[i] = ESK[30 - i];
				SK[i + 1] = ESK[31 - i];
			}

			int textsz = text.Length;

			if ((textsz & 7) != 0 || textsz == 0) {
				throw new SystemException(string.Format("Invalid des crypt text length {0}", textsz));
			}

			byte [] buffer = output;

			for (i=0;i<textsz;i+=8) {
				des_crypt(SK, text, i, buffer, i);
			}
			int padding = 1;
			for (i=textsz-1;i>=textsz-8;i--) {
				if (buffer[i] == 0) {
					padding++;
				} else if (buffer[i] == 0x80) {
					break;
				} else {
					throw new SystemException("Invalid des crypt text");
				}
			}
			if (padding > 8) {
				throw new SystemException("Invalid des crypt text");
			}
			return textsz - padding;
		}

		private static void Hash(byte [] str, byte [] key) {
			int sz = str.Length;
			UInt32 djb_hash = 5381;
			UInt32 js_hash = 1315423911;

			int i;
			for (i=0;i<sz;i++) {
				byte c = (byte)str[i];
				djb_hash += (djb_hash << 5) + c;
				js_hash ^= ((js_hash << 5) + c + (js_hash >> 2));
			}

			key[0] = (byte)(djb_hash & 0xff);
			key[1] = (byte)((djb_hash >> 8) & 0xff);
			key[2] = (byte)((djb_hash >> 16) & 0xff);
			key[3] = (byte)((djb_hash >> 24) & 0xff);

			key[4] = (byte)(js_hash & 0xff);
			key[5] = (byte)((js_hash >> 8) & 0xff);
			key[6] = (byte)((js_hash >> 16) & 0xff);
			key[7] = (byte)((js_hash >> 24) & 0xff);
		}

		public static byte[] HashKey(byte [] key) {
			byte [] realkey = new byte[8];
			Hash(key, realkey);
			return realkey;
		}

		public static string HexEncode(byte [] text)
		{
			StringBuilder sb = new StringBuilder(SMALL_CHUNK);

			for (int i = 0; i < text.Length; i++)
				sb.Append(text[i].ToString("x2"));

			return sb.ToString();
		}

		public static byte[] HexDecode(string text)
		{
			byte[] data = new byte[text.Length / 2];

			for (int i = 0; i < text.Length / 2; i++) {
				data[i] = Convert.ToByte(text.Substring(i * 2, 2), 16);
			}

			return data;
		}

		// Constants are the integer part of the sines of integers (in radians) * 2^32.
		private static readonly UInt32 [] k = new UInt32[64] {
			0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee ,
			0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501 ,
			0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be ,
			0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ,
			0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa ,
			0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8 ,
			0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed ,
			0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a ,
			0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c ,
			0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70 ,
			0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05 ,
			0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 ,
			0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039 ,
			0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1 ,
			0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1 ,
			0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 
		};
 
		// r specifies the per-round shift amounts
		private static readonly int [] r = new int[64] {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
							5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
							4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
							6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

		private static UInt32 LEFTROTATE(UInt32 x, int c) { 
			return (((x) << (c)) | ((x) >> (32 - (c)))); 
		}

		private static void digest_md5(UInt32 [] w /*16*/, UInt32 [] result /*4*/) {
			UInt32 a, b, c, d, f, g, temp;
			UInt32 i;           
		
			a = 0x67452301u;
			b = 0xefcdab89u;
			c = 0x98badcfeu;
			d = 0x10325476u;

			for(i = 0; i<64; i++) {
				if (i < 16) {
					f = (b & c) | ((~b) & d);
					g = i;
				} else if (i < 32) {
					f = (d & b) | ((~d) & c);
					g = (5*i + 1) % 16;
				} else if (i < 48) {
					f = b ^ c ^ d;
					g = (3*i + 5) % 16; 
				} else {
					f = c ^ (b | (~d));
					g = (7*i) % 16;
				}

				temp = d;
				d = c;
				c = b;
				b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
				a = temp;
			}

			result[0] = a;
			result[1] = b;
			result[2] = c;
			result[3] = d;
		}

		// hmac64 use md5 algorithm without padding, and the result is (c^d .. a^b)
		private static void hmac(UInt32 [] x /*2*/, UInt32 [] y /*2*/, UInt32 [] result /*2*/) {
			UInt32 [] w = new UInt32[16];
			UInt32 [] r = new UInt32[4];
			int i;
			for (i=0;i<16;i+=4) {
				w[i] = x[1];
				w[i+1] = x[0];
				w[i+2] = y[1];
				w[i+3] = y[0];
			}

			digest_md5(w,r);

			result[0] = r[2]^r[3];
			result[1] = r[0]^r[1];
		}

		private static void hmac_md5(UInt32 [] x /*2*/, UInt32 [] y /*2*/, UInt32 [] result /*2*/) {
			UInt32 [] w = new UInt32[16];
			UInt32 [] r = new UInt32[4];
			int i;
			for (i=0;i<12;i+=4) {
				w[i] = x[0];
				w[i+1] = x[1];
				w[i+2] = y[0];
				w[i+3] = y[1];
			}

			w[12] = 0x80;
			w[13] = 0;
			w[14] = 384;
			w[15] = 0;

			digest_md5(w,r);

			result[0] = (r[0] + 0x67452301u) ^ (r[2] + 0x98badcfeu);
			result[1] = (r[1] + 0xefcdab89u) ^ (r[3] + 0x10325476u);
		}

		private static void read64(byte [] x, byte [] y, UInt32 [] xx /*2*/, UInt32 [] yy /*2*/) {
			if (x.Length != 8) {
				throw new SystemException("Invalid uint64 x");
			}
			
			if (x.Length != 8) {
				throw new SystemException("Invalid uint64 y");
			}

			xx[0] = (UInt32)(x[0] | x[1]<<8 | x[2]<<16 | x[3]<<24);
			xx[1] = (UInt32)(x[4] | x[5]<<8 | x[6]<<16 | x[7]<<24);
			yy[0] = (UInt32)(y[0] | y[1]<<8 | y[2]<<16 | y[3]<<24);
			yy[1] = (UInt32)(y[4] | y[5]<<8 | y[6]<<16 | y[7]<<24);
		}

		private static byte [] pushqword(UInt32 [] result) {
			byte [] tmp = new byte [8];

			tmp[0] = (byte)(result[0] & 0xff);
			tmp[1] = (byte)((result[0] >> 8 )& 0xff);
			tmp[2] = (byte)((result[0] >> 16 )& 0xff);
			tmp[3] = (byte)((result[0] >> 24 )& 0xff);
			tmp[4] = (byte)(result[1] & 0xff);
			tmp[5] = (byte)((result[1] >> 8 )& 0xff);
			tmp[6] = (byte)((result[1] >> 16 )& 0xff);
			tmp[7] = (byte)((result[1] >> 24 )& 0xff);

			return tmp;
		}

		public static byte [] HMAC64(byte [] inputX, byte [] inputY) {
			UInt32 [] x = new UInt32[2], y = new UInt32[2];
			read64(inputX, inputY, x, y);
			UInt32 [] result = new UInt32[2];
			hmac(x, y, result);
			return pushqword(result);
		}

		public static byte [] HMAC64_MD5(byte [] inputX, byte [] inputY) {
			UInt32 [] x = new UInt32[2], y = new UInt32[2];
			read64(inputX, inputY, x, y);
			UInt32 [] result = new UInt32[2];
			hmac_md5(x, y, result);
			return pushqword(result);
		}

		public static byte[] MD5(byte [] data) {
			return System.Security.Cryptography.MD5.Create().ComputeHash(data);
		}

        public static byte[] MD5(byte[] data, int offset, int count)
        {
            return System.Security.Cryptography.MD5.Create().ComputeHash(data, offset, count);
        }

        public static byte[] HMAC_MD5(byte [] key, byte [] data) {
            System.Security.Cryptography.HMACMD5 hmacmd5 = new System.Security.Cryptography.HMACMD5(key);
            return hmacmd5.ComputeHash(data);
		}

		public static byte[] SHA1(byte [] data) {
			return System.Security.Cryptography.SHA1.Create().ComputeHash(data);
		}

		public static byte[] HMAC_SHA1(byte [] key, byte [] data) {
            System.Security.Cryptography.HMACSHA1 hmacsha1 = new System.Security.Cryptography.HMACSHA1(key);
            return hmacsha1.ComputeHash(data);
		}

		public static byte[] HMAC_HASH(byte [] x, byte [] text) {
			UInt32 [] key = new UInt32[2];
			if (x.Length != 8) {
				throw new SystemException("Invalid uint64 key");
			}
			key[0] = (UInt32)(x[0] | x[1]<<8 | x[2]<<16 | x[3]<<24);
			key[1] = (UInt32)(x[4] | x[5]<<8 | x[6]<<16 | x[7]<<24);
			byte [] h = new byte[8];
			Hash(text,h);
			UInt32 [] htext= new UInt32[8];
			htext[0] = (UInt32)(h[0] | h[1]<<8 | h[2]<<16 | h[3]<<24);
			htext[1] = (UInt32)(h[4] | h[5]<<8 | h[6]<<16 | h[7]<<24);
			UInt32 [] result = new UInt32[2];
			hmac(htext,key,result);
			return pushqword(result);
		}

		public static string Base64Encode(byte [] data) {
			return Convert.ToBase64String(data);
		}

		public static byte[] Base64Decode(string s) {
			return Convert.FromBase64String(s);
		}

		// The biggest 64bit prime
		private static readonly UInt64 P = 0xffffffffffffffc5u;

		private static UInt64 mul_mod_p(UInt64 a, UInt64 b) {
			UInt64 m = 0;
			while(b != 0) {
				if((b&1) != 0) {
					UInt64 t = P-a;
					if ( m >= t) {
						m -= t;
					} else {
						m += a;
					}
				}
				if (a >= P - a) {
					a = a * 2 - P;
				} else {
					a = a * 2;
				}
				b>>=1;
			}
			return m;
		}

		private static UInt64 pow_mod_p(UInt64 a, UInt64 b) {
			if (b==1) {
				return a;
			}
			UInt64 t = pow_mod_p(a, b>>1);
			t = mul_mod_p(t,t);
			if ((b % 2) != 0) {
				t = mul_mod_p(t, a);
			}
			return t;
		}

		// calc a^b % p
		static UInt64 powmodp(UInt64 a, UInt64 b) {
			if (a > P)
				a%=P;
			return pow_mod_p(a,b);
		}

		static byte [] push64(UInt64 r) {
			byte [] tmp = new byte[8];
			tmp[0] = (byte)(r & 0xff);
			tmp[1] = (byte)((r >> 8 )& 0xff);
			tmp[2] = (byte)((r >> 16 )& 0xff);
			tmp[3] = (byte)((r >> 24 )& 0xff);
			tmp[4] = (byte)((r >> 32 )& 0xff);
			tmp[5] = (byte)((r >> 40 )& 0xff);
			tmp[6] = (byte)((r >> 48 )& 0xff);
			tmp[7] = (byte)((r >> 56 )& 0xff);

			return tmp;
		}

		public static byte[] DHSecret(byte [] inputX, byte [] inputY) {
			UInt32 [] x = new UInt32[2], y = new UInt32[2];
			read64(inputX, inputY, x, y);
			UInt64 xx = (UInt64)x[0] | (UInt64)x[1]<<32;
			UInt64 yy = (UInt64)y[0] | (UInt64)y[1]<<32;
			if (xx == 0 || yy == 0)
				throw new SystemException("Can't be 0");
			UInt64 r = powmodp(xx, yy);

			return push64(r);
		}

		private static readonly UInt64 G = 5;

		public static byte[] DHExchange(byte [] x) {
			if (x.Length != 8) {
				throw new SystemException("Invalid dh uint64 key");
			}
			UInt32 [] xx = new UInt32[2];
			xx[0] = (UInt32)(x[0] | x[1]<<8 | x[2]<<16 | x[3]<<24);
			xx[1] = (UInt32)(x[4] | x[5]<<8 | x[6]<<16 | x[7]<<24);

			UInt64 x64 = (UInt64)xx[0] | (UInt64)xx[1]<<32;
			if (x64 == 0)
				throw new SystemException("Can't be 0");

			UInt64 r = powmodp(G, x64);
			return push64(r);
		}
	}
}
