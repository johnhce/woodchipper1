package com.goodlicious.coinlibrary;

import java.math.BigInteger;

public class Base58CheckEncoding {
    private static final String ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final BigInteger BIG0 = BigInteger.ZERO;
    private static final BigInteger BIG58 = BigInteger.valueOf(58);

    public static String convertToBase58(String hash) {
        return convertToBase58(hash, 16);
    }

    public static String convertToBase58(String hash, int base) {
        BigInteger x;
        if (base == 16 && hash.substring(0, 2).equals("0x")) {
            x = new BigInteger(hash.substring(2), 16);
        } else {
            x = new BigInteger(hash, base);
        }

        StringBuilder sb = new StringBuilder();
        while (x.compareTo(BIG0) > 0) {
            int r = x.mod(BIG58).intValue();
            sb.append(ALPHABET.charAt(r));
            x = x.divide(BIG58);
        }
System.out.println("BASE58::result non-rev = " + sb.toString());
        return sb.reverse().toString();
    }

    // this probably won't work!
    public static String convertToBase58LeftToRight(String hash)
    {
    	// offset bit masks
    	byte[] bitMasks1 = { (byte)0b11111100, (byte)0b00000011, (byte)0b00001111, (byte)0b00111111 };
    	byte[] bitMasks2 = { (byte)0b00000000, (byte)0b11110000, (byte)0b11000000, (byte)0b00000000 };
        StringBuilder sb = new StringBuilder();
        int bitMaskIndex = 0;
        int carry = 0;
    	for (int n = 0; n < hash.length();)
    	{
    		// grab 6 bits at a time
    		byte sixBitValue = 0;
    		switch(bitMaskIndex)
    		{
    			case 0:
        			// need to grab only 1 byte
        			sixBitValue = (byte)((hash.charAt(n) & bitMasks1[bitMaskIndex]) / 4);

        			// advance character index by 1
        			n++;
    				break;
    			case 1:
        			// grab 2 bytes and assemble a 6-bit quantity
//TODO what if there's only 1 byte left?
        			sixBitValue = (byte)((hash.charAt(n) & bitMasks1[bitMaskIndex]) + ((hash.charAt(n+1) & bitMasks2[bitMaskIndex]) / 16));

        			// advance character index by 2
        			n += 2;
    				break;
    			case 2:
//TODO what if there's only 1 byte left?
        			// grab 2 bytes and assemble a 6-bit quantity
        			sixBitValue = (byte)((hash.charAt(n) & bitMasks1[bitMaskIndex]) + ((hash.charAt(n+1) & bitMasks2[bitMaskIndex]) / 64));

        			// advance character index by 2
        			n += 2;
    				break;
    			case 3:
        			// need to grab only 1 byte
        			sixBitValue = (byte)(hash.charAt(n) & bitMasks1[bitMaskIndex]);

        			// advance character index by 1
        			n++;
    				break;
    		}
 
    		// if > 58, carry the mod
    		if ((int)sixBitValue + carry > 58)
    		{
    			sb.append("z");
    			carry = ((int)sixBitValue + carry) % 58;
    		}
    		bitMaskIndex = ++bitMaskIndex % 4;
    	}
    	return sb.toString();
    }
}
