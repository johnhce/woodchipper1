package com.goodlicious.coinlibrary;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;

import javax.xml.bind.DatatypeConverter;

import gnu.crypto.Registry;
import gnu.crypto.hash.HashFactory;
import gnu.crypto.hash.IMessageDigest;

/*
 * The task from the Woodchipper:
 * 
 * Using nothing but elliptical curve libs to generate a private/public keypair, write an address creator function
 * Take a network integer parameter that specifies which type of address should be generated
 * Use the method described in Mastering Bitcoin
 * "type of address" = Testnet vs Mainnet
 * Don’t worry about more exotic address forms, like SegWit or bech32
 * You can also use sha256 and ripemd160 methods from hash libs
 * And if you’re feeling lazy you can also use a base58 converter if you don’t want to write one
*/
public class CoinLibrary {

	private final static String HEX_CHARS = "0123456789ABCDEF";

	private boolean isTestNet;	// true if we're building an address for testnet

	public CoinLibrary(boolean isTestNet)
	{
		this.isTestNet = isTestNet;
	}

    static private String adjustTo64(String s) {
        switch(s.length()) {
        case 62: return "00" + s;
        case 63: return "0" + s;
        case 64: return s;
        default:
            throw new IllegalArgumentException("not a valid key: " + s);
        }
    }

    public KeyPair getKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException
	{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");
        keyPairGenerator.initialize(ecSpec);
        return keyPairGenerator.generateKeyPair();
	}

    public String generateBitcoinAddressRich() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, UnsupportedEncodingException
    {
        KeyPair keypair = getKeyPair();
        ECPrivateKey privKey = (ECPrivateKey) keypair.getPrivate();
        System.out.println("PRIVATE KEY                = " + adjustTo64(privKey.getS().toString(16)));
        ECPublicKey pubKey = (ECPublicKey) keypair.getPublic();
        ECPoint pt = pubKey.getW();
        String sx = adjustTo64(pt.getAffineX().toString(16)).toUpperCase();
        System.out.println("sx                         = " + sx);
        String sy = adjustTo64(pt.getAffineY().toString(16)).toUpperCase();
        System.out.println("sy                         = " + sy);
        String pubKeyString = "04" + sx + sy;
        System.out.println("pubKeyString               = " + pubKeyString);
        //x doesn't work -  byte[] pubKeyBytes = pubKeyString.getBytes("UTF-8");
        byte[] pubKeyBytes = new BigInteger(pubKeyString,16).toByteArray();
        //x doesn't work -  byte[] pubKeyBytes = hexToByteArray(pubKeyString);
        System.out.println("pubKeyBytes                = " + bytesToHex(pubKeyBytes));

        // SHA-256
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] sha256Bytes = messageDigest.digest(pubKeyBytes);//x Bytes);
        System.out.println("sha256Bytes                = " + bytesToHex(sha256Bytes));

        // RIPEMD-160
        byte[] ripemd160Bytes = encodeRIPEMD160(sha256Bytes);
        //x doesn't work - byte[] ripemd160Bytes2 = encodeRIPEMD160(new String(sha256Bytes).getBytes("UTF-8"));
        System.out.println("ripemd160Bytes             = " + bytesToHex(ripemd160Bytes));

        // prefix as mainnet (0x00) or testnet (0x6f)
        byte prefix = (byte)(isTestNet ? 0x6F : 0x00);
        System.out.println("prefix                     = " + prefix);

        // compute checksum
		byte[] prefixPlusRipemd = new byte[1 + ripemd160Bytes.length];
		prefixPlusRipemd[0] = (byte) prefix;
		for (int n = 0; n < ripemd160Bytes.length; n++) prefixPlusRipemd[1+n] = ripemd160Bytes[n];
		System.out.println("prefixPlusRipemd           = " + bytesToHex(prefixPlusRipemd));

		byte[] checksumBytes = messageDigest.digest(messageDigest.digest(prefixPlusRipemd));
		System.out.println("checksumBytes              = " + bytesToHex(checksumBytes));

		// add checksum to end
		byte[] prefixPlusRipemdPlusChecksum = new byte[prefixPlusRipemd.length + 4];
		for (int n = 0; n < prefixPlusRipemd.length; n++) prefixPlusRipemdPlusChecksum[n] = prefixPlusRipemd[n];
		for (int n = 0; n < 4; n++) prefixPlusRipemdPlusChecksum[n+prefixPlusRipemd.length] = checksumBytes[n];

		// transform to hex digits
		String hexString = DatatypeConverter.printHexBinary(prefixPlusRipemdPlusChecksum);
		System.out.println("prefix + ripemd + checksum = " + hexString);

		// Base58Check
		String btcAddr = Base58CheckEncoding.convertToBase58(hexString, 16);

		// since the BigInteger based B58 routine above will strip leading zeros, we will prefix the result with '1'
		// which would have happened without the stripping
		return "1" + btcAddr;
    }

	/**
	 * Return base58(ripemd160(sha256(pubKey)))
	 * @return
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws UnsupportedEncodingException 
	 */
	public String generateBitcoinAddress() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		KeyPair keypair = getKeyPair();
		ECPrivateKey privKey = (ECPrivateKey) keypair.getPrivate();
		System.out.println("PRIVATE KEY                = " + adjustTo64(privKey.getS().toString(16)));
		ECPublicKey pubKey = (ECPublicKey) keypair.getPublic();
		ECPoint pt = pubKey.getW();
		String sx = adjustTo64(pt.getAffineX().toString(16)).toUpperCase();
		System.out.println("sx                         = " + sx);
		String sy = adjustTo64(pt.getAffineY().toString(16)).toUpperCase();
		System.out.println("sy                         = " + sy);
		String pubKeyString = "04" + sx + sy;
		System.out.println("pubKeyString               = " + pubKeyString);
		byte[] pubKeyBytes = pubKeyString.getBytes("UTF-8");
//x doesn't work -	byte[] pubKeyBytes = hexToByteArray(pubKeyString);
		System.out.println("pubKeyBytes                = " + bytesToHex(pubKeyBytes));

		// SHA-256
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] sha256Bytes = messageDigest.digest(pubKeyString.getBytes("UTF-8"));//x Bytes);
        System.out.println("sha256Bytes                = " + bytesToHex(sha256Bytes));

/*TEST
{//x
	// CORRECT and NUTTY
	byte[] pubKeyBytesA = pubKeyString.getBytes("UTF-8");
	System.out.println("len A bytes = " + pubKeyBytesA.length);
    byte[] sha256BytesA = messageDigest.digest(pubKeyBytesA);
    System.out.println("sha256BytesA               = " + bytesToHex(sha256BytesA));

    // INCORRECT and SANE
	byte[] pubKeyBytesB = hexToByteArray(pubKeyString);
	System.out.println("len B bytes = " + pubKeyBytesB.length);
    byte[] sha256BytesB = messageDigest.digest(pubKeyBytesB);
    System.out.println("sha256BytesB               = " + bytesToHex(sha256BytesB));
}*/

        // RIPEMD-160
        byte[] ripemd160Bytes = encodeRIPEMD160(sha256Bytes);
System.out.println("ripemd160Bytes             = " + bytesToHex(ripemd160Bytes));
//x byte[] ripemd160Bytes2 = encodeRIPEMD160(new String(sha256Bytes).getBytes("UTF-8"));
//x System.out.println("ripemd160Bytes2             = " + bytesToHex(ripemd160Bytes2));

//x ripemd160Bytes = hexToByteArray("B69490B2AE1D866FA98887E71BE6C5A0A553BC32");	// FORCE IT!!!

		// prefix as mainnet (0x00) or testnet (0x6f)
		byte prefix = (byte)(isTestNet ? 0x6F : 0x00);
System.out.println("prefix                     = " + prefix);

		// compute checksum
//x old		byte[] prefixPlusRipemd = (prefix + ripemd160Bytes.toString()).getBytes();
		byte[] prefixPlusRipemd = new byte[1 + ripemd160Bytes.length];
		prefixPlusRipemd[0] = (byte) prefix;
		for (int n = 0; n < ripemd160Bytes.length; n++) prefixPlusRipemd[1+n] = ripemd160Bytes[n];
System.out.println("prefixPlusRipemd           = " + bytesToHex(prefixPlusRipemd));

		byte[] checksumBytes = messageDigest.digest(messageDigest.digest(prefixPlusRipemd));
System.out.println("checksumBytes              = " + bytesToHex(checksumBytes));

		// add checksum to end
		byte[] prefixPlusRipemdPlusChecksum = new byte[prefixPlusRipemd.length + 4];
		for (int n = 0; n < prefixPlusRipemd.length; n++) prefixPlusRipemdPlusChecksum[n] = prefixPlusRipemd[n];
		for (int n = 0; n < 4; n++) prefixPlusRipemdPlusChecksum[n+prefixPlusRipemd.length] = checksumBytes[n];
        // transform to hex digits
		String hexString = DatatypeConverter.printHexBinary(prefixPlusRipemdPlusChecksum);
System.out.println("prefix + ripemd + checksum = " + hexString);

        // Base58Check
        String btcAddr = Base58CheckEncoding.convertToBase58(hexString, 16);
//x LATER!!! System.out.println("btcAddrLeftToRightEncoder  = 1" + Base58CheckEncoding.convertToBase58LeftToRight(hexString));

        // since the BigInteger based B58 routine above will strip leading zeros, we will prefix the result with '1'
        // which would have happened without the stripping
		return "1" + btcAddr;
//x old        return prefix + btcAddr + checksumBytes.toString().substring(0, 3);
	}

	public String bytesToHex(byte[] bs)
	{
		StringBuilder sb = new StringBuilder();
		for (byte b : bs)
		{
			sb.append(HEX_CHARS.charAt((b & 0xF0) >>> 4));	// unsigned shift right (divide by 16)
			sb.append(HEX_CHARS.charAt(b & 0x0F));
		}
		return sb.toString();
	}

	/**
	 * CAUTION: Assumes a correctly sized string - must be even number of characters!!!
	 * 
	 * @param hexString
	 * @return
	 */
	public byte[] hexToByteArray(String hexString)
	{
		byte[] ba = new byte[hexString.length() / 2];
		int baIdx = 0;
		for (int n = 0; n < hexString.length(); n += 2)
		{
			byte b = (byte)(HEX_CHARS.indexOf(hexString.charAt(n)) * 16 + HEX_CHARS.indexOf(hexString.charAt(n+1)));
//System.out.println("byte:"+b);//x
			ba[baIdx++] = b;
		}
//System.out.println("baIdx:"+baIdx);//x
		return ba;
	}

	public byte[] encodeRIPEMD160(byte[] encBytes)
	{
		IMessageDigest md = HashFactory.getInstance(Registry.RIPEMD160_HASH);
		md.update(encBytes, 0, encBytes.length);
	    return md.digest();
	}

	public static void main(String[] args)
	{
		try
		{
			// if param = 1, we are on test net
			CoinLibrary cl = new CoinLibrary(args.length > 0  &&  args[0].equals("1"));
			System.out.println("new btc addr = " + cl.generateBitcoinAddressRich());
		}
		catch(Exception ex)
		{
			ex.printStackTrace();
		}
	}
}
