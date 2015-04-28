package wots;

import files.PseudorandomFunction;
import files.ByteUtils;
import files.IntegerUtils;
import files.MathUtils;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Moritz Horsch <horsch@cdc.informatik.tu-darmstadt.de>
 */
public class WinternitzOTS implements OTS {

    // Logger
    private static final Logger logger = LoggerFactory.getLogger(WinternitzOTS.class);
    // Lengths 
    private int m, l, l1, l2;
    // Winternitz parameter
    private int w;
    // Security parameter
    private int n;
    // Pseudorandom function
    private PseudorandomFunction prf;
    // Random value
    private byte[] x;
    // Private key
    private byte[][] privateKey;
    // Public key
    private byte[][] publicKey;
    // Message digest
    private MessageDigest digest;

    /**
     * Creates a new Winternitz OTS.
     *
     * @param w Winternitz parameter w
     */
    public WinternitzOTS(int w) {
	this.w = w;

	try {
	    digest = MessageDigest.getInstance("SHA-256");
	} catch (NoSuchAlgorithmException e) {
	    logger.error("Exception", e);
	    throw new RuntimeException(e);
	}

	calculateLengths();
    }

    /**
     * Initialize the Winternitz OTS.
     *
     * @param prf Pseudorandom function
     * @param x Random value X
     */
    public void init(PseudorandomFunction prf, byte[] x) {
	this.prf = prf;
	this.x = x;
	this.n = prf.getLength();

	logger.debug("Using {} as PRF", prf.getClass().getName());
	logger.debug("n: {}", n);
	logger.trace("X: {} ({} bytes)", new Object[]{ByteUtils.toHexString(x), x.length});
    }

    /**
     * Sets the message digest to hash messages.
     *
     * @param digest Message digest
     */
    public void setMessageDigest(MessageDigest digest) {
	this.digest = digest;
	// Update lengths
	calculateLengths();
    }

    /**
     * Generates a key pair.
     *
     * @param seed Seed
     */
    public void generateKeyPair(byte[] seed) {
	generatePrivateKey(seed);
	generatePublicKey();
    }

    /**
     * Generates the private key.
     *
     * @param seed Seed
     */
    public void generatePrivateKey(byte[] seed) {
	privateKey = new byte[l][n];

	for (int i = 0; i < l; i++) {
	    byte[] key = new byte[prf.getLength()];
	    byte[] input = IntegerUtils.toByteArray(i);
	    System.arraycopy(input, 0, key, key.length - input.length, input.length);
	    privateKey[i] = prf.apply(key, seed);
	}

	logger.debug("Generate private key");
	logger.trace("SK: {} ...", ByteUtils.toHexString(ByteUtils.convert(privateKey), 10));
	logger.trace("Seed: {} ...", ByteUtils.toHexString(seed, 10));
	logger.trace("Private key: {} ({} bytes)", new Object[]{ByteUtils.toHexString(privateKey),});
    }

    /**
     * Generates the public key.
     *
     */
    public void generatePublicKey() {
	publicKey = new byte[l][n];

	for (int i = 0; i < l; i++) {
	    byte[] hash = new byte[n];
	    System.arraycopy(privateKey[i], 0, hash, 0, hash.length);

	    for (int j = 0; j < w - 1; j++) {
		hash = prf.apply(x, hash);
	    }

	    publicKey[i] = hash;
	}

	logger.debug("Generate public key");
	logger.debug("PK: {} ...", ByteUtils.toHexString(ByteUtils.convert(publicKey), 10));
	logger.trace("Public key: {} ({} bytes)", new Object[]{ByteUtils.toHexString(publicKey), l * n});
    }

    /**
     * Creates a public key from given message and signature.
     *
     * @param message Message
     * @param signature Signature
     * @return Public key
     */
    public byte[][] generatePublicKey(byte[] message, byte[] signature) {
	byte[][] key = new byte[l][n];

	// Hash message
	message = digest.digest(message);
	// Calculate exponent b
	byte[] b = calculateExponentB(message);

	for (int i = 0; i < l; i++) {
	    byte[] hash = new byte[n];
	    System.arraycopy(signature, hash.length * i, hash, 0, hash.length);

	    // Hash x (w - 1 - b_i) times
	    for (int j = 0; j < (w - 1 - (b[i] & 0xFF)); j++) {
		hash = prf.apply(x, hash);
	    }

	    key[i] = hash;
	}

	return key;
    }

    /**
     * Signs a message.
     *
     * @param message Message
     * @return Signature of the message
     */
    public byte[] sign(byte[] message) {
	byte[] signature = new byte[l * n];

	// Hash message
	message = digest.digest(message);
	// Calculate exponent b
	byte[] b = calculateExponentB(message);

	for (int i = 0; i < l; i++) {
	    byte[] hash = new byte[n];
	    System.arraycopy(privateKey[i], 0, hash, 0, hash.length);

	    for (int j = 0; j < (b[i] & 0xFF); j++) {
		hash = prf.apply(x, hash);
	    }

	    System.arraycopy(hash, 0, signature, hash.length * i, hash.length);
	}

	return signature;
    }

    /**
     * Verifies a the signature of a message.
     *
     * @param message Message
     * @param signature Signature
     * @return True if the signature is valid, otherwise false
     */
    public boolean verify(byte[] message, byte[] signature) {
	// Hash message
	message = digest.digest(message);
	// Calculate exponent b
	byte[] b = calculateExponentB(message);

	for (int i = 0; i < l; i++) {
	    byte[] hash = new byte[n];
	    System.arraycopy(signature, hash.length * i, hash, 0, hash.length);

	    // Hash x (w - 1 - b_i) times
	    for (int j = 0; j < (w - 1 - (b[i] & 0xFF)); j++) {
		hash = prf.apply(x, hash);
	    }

	    // Compare sigma_i with pk_i
	    if (!Arrays.equals(hash, publicKey[i])) {
		return false;
	    }
	}

	return true;
    }

    /**
     * Calculate the lengths l1, l2, and l.
     */
    private void calculateLengths() {
	m = digest.getDigestLength() * 8;
	l1 = (int) Math.ceil((double) m / MathUtils.log2(w));
	l2 = (int) Math.floor(MathUtils.log2(l1 * (w - 1)) / MathUtils.log2(w)) + 1;
	l = l1 + l2;

	logger.debug("Using Winternitz OTS with w={} and m={}", new Object[]{w, m});
	logger.debug("Lengths are: l1={}, l2={}, and l={}", new Object[]{l1, l2, l});
    }

    /**
     * Calculate the exponent b (b_1, ..., b_l).
     *
     * @param message Message
     * @return Exponent b
     */
    private byte[] calculateExponentB(byte[] message) {
	// Convert message to base w representation
	byte[] mBaseW = convertToBaseW(message, l1);

	// Calculate checksum c
	BigInteger checksum = BigInteger.ZERO;
	for (int i = 0; i < l1; i++) {
	    checksum = checksum.add(BigInteger.valueOf(w - 1 - (mBaseW[i] & 0xFF)));
	}

	// Convert checksum to base w representation
	byte[] checksumBaseW = convertToBaseW(checksum.toByteArray(), l2);

	// Concatenate message and checksum
	byte[] b = ByteUtils.concatenate(mBaseW, checksumBaseW);

	return b;
    }

    /**
     * Convert the input to a base w representation.
     *
     * @param input Input
     * @param length Length of the output
     * @return Base w representation of the input
     */
    private byte[] convertToBaseW(byte[] input, int length) {
	BigInteger i = new BigInteger(1, input);
	BigInteger b = BigInteger.valueOf(w);
	ArrayList<Byte> result = new ArrayList<Byte>();

	while (i.compareTo(BigInteger.ZERO) != 0) {
	    result.add(i.mod(b).byteValue());
	    i = i.divide(b);
	}

	byte[] ret = new byte[length];
	for (int j = (length - result.size()); j < ret.length; j++) {
	    ret[j] = result.get(ret.length - j - 1).byteValue();
	}

	return ret;
    }

    /**
     * Returns the private key.
     *
     * @return Private key
     */
    public byte[][] getPrivateKey() {
	return privateKey;
    }

    /**
     * Returns the public key.
     *
     * @return Public key
     */
    public byte[][] getPublicKey() {
	return publicKey;
    }

    /**
     * Returns the length l.
     * The size of the signature, public, and private key is l * n.
     *
     * @return Length l
     */
    public int getLength() {
	return l;
    }

    /**
     * Returns the message length.
     *
     * @return Message length
     */
    public int getMessageLength() {
	return m;
    }
    
    public void setPrivateKey(byte[][] p) {
    	this.privateKey = p;
    }
    
    public void setPublicKey(byte[][] p) {
    	this.publicKey = p;
    }
}
