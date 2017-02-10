

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

/**
 * The PGP encrypt and sign processor
 */
public class PgpEncryptAndSignProcessor {

	private static final int BUFFER_SIZE = 1 << 16; // should always be power of 2(one shifted bitwise 16 places)
	private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
	private static final String EMBEDDED_FILENAME = "_RUNTIME.txt"; //$NON-NLS-1$

	private final PgpEncryptAndSignMode mode;
	private final PGPPublicKey encryptKey;
	private final PGPPublicKey signPublicKey;
	private final PGPPrivateKey signPrivateKey;
	private final boolean armor;
	private final int compressionAlgorithm;
	private final int symmetricKeyAlgorithm;
	private final int hashAlgorithm;
	private final boolean withIntegrityCheck;

	PgpEncryptAndSignProcessor(
								final PgpEncryptAndSignMode mode,
								final PGPPublicKey encryptKey,
								final PGPSecretKey signKey,
								final String passphraseForSignKey,
								final boolean armor,
								final int compressionAlgorithm,
								final int symmetricKeyAlgorithm,
								final int hashAlgorithm,
								final boolean withIntegrityCheck) throws PGPException {
		this.mode = mode;
		this.encryptKey = encryptKey;
		
		this.signPublicKey = signKey.getPublicKey();
		this.signPrivateKey = signKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider(BC).build(passphraseForSignKey.toCharArray()));

		this.armor = armor;
		this.compressionAlgorithm = compressionAlgorithm;
		this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
		this.hashAlgorithm = hashAlgorithm;
		this.withIntegrityCheck = withIntegrityCheck;
	}

	/**
	 * Process encrypt and/or sign operations
	 *
	 * @param in the input stream
	 * @param out the output stream
	 * @throws IOException thrown if there is an error with IO stream
	 * @throws PGPException thrown if there is an error with PGP operation
	 */
	public void process(final InputStream in, final OutputStream out) throws IOException, PGPException {
		final OutputStream targetOut;
		if (this.armor) {
			targetOut = new ArmoredOutputStream(out);
		} else {
			targetOut = out;
		}

		try {
			switch (this.mode) {
				case SignThenEncrypt:
					signThenEncrypt(in, targetOut);
					break;
				case EncryptThenSign:
					encryptThenSign(in, targetOut);
					break;
				case SignOnly:
					sign(in, targetOut);
					break;
				case EncryptOnly:
					encrypt(in, targetOut);
					break;
				default:
					throw new IllegalArgumentException();
			}
		} finally {
			if (this.armor) {
				targetOut.close();
			}
		}
	}

	/**
	 * The data will be signed first, then compressed, encrypted at the last
	 */
	private void signThenEncrypt(final InputStream sourceInputStream, final OutputStream targetOutputStream) throws IOException, PGPException {
		assert this.encryptKey != null;
		assert this.signPublicKey != null;

		// encryption
		final PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(
				new JcePGPDataEncryptorBuilder(this.symmetricKeyAlgorithm).setWithIntegrityPacket(this.withIntegrityCheck).setSecureRandom(new SecureRandom())
						.setProvider(BC));
		try {
			encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(this.encryptKey).setProvider(BC));

			try (OutputStream encryptedOut = encryptedDataGenerator.open(targetOutputStream, new byte[BUFFER_SIZE])) {

				// sign the data
				sign(sourceInputStream, encryptedOut);
			}
		} finally {
			encryptedDataGenerator.close();
		}
	}

	/**
	 * The data will be signed first, then compressed
	 */
	private void sign(final InputStream sourceInputStream, final OutputStream targetOutputStream) throws IOException, PGPException {
		assert this.signPublicKey != null;

		// compression
		final PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(this.compressionAlgorithm);
		try {
			try (OutputStream compressedOut = compressedDataGenerator.open(targetOutputStream)) {

				// signature
				final PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
						new JcaPGPContentSignerBuilder(this.signPublicKey.getAlgorithm(), this.hashAlgorithm).setProvider(BC));

				signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, this.signPrivateKey);

				final Iterator<?> it = this.signPublicKey.getUserIDs();
				// Just the first one!
				if (it.hasNext()) {
					final PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
					final String userId = (String) it.next();

					spGen.setSignerUserID(false, userId);
					signatureGenerator.setHashedSubpackets(spGen.generate());
				}
				signatureGenerator.generateOnePassVersion(false).encode(compressedOut);

				// Create the Literal Data generator output stream
				final PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
				try {
					// create output stream
					try (final OutputStream literalOut = literalDataGenerator
							.open(compressedOut, PGPLiteralData.BINARY, EMBEDDED_FILENAME, new Date(), new byte[BUFFER_SIZE])) {

						// read input file and write to target out stream using a buffer
						final byte[] buf = new byte[BUFFER_SIZE];
						int length;
						while ((length = sourceInputStream.read(buf, 0, buf.length)) > 0) {
							literalOut.write(buf, 0, length);
							signatureGenerator.update(buf, 0, length);
						}
					}
				} finally {
					literalDataGenerator.close();
				}
				signatureGenerator.generate().encode(compressedOut);

			}
		} finally {
			compressedDataGenerator.close();
		}
	}

	/**
	 * The data will be encrypted, then signed. There will be no compression,
	 * because compression is inefficient on encrypted data.
	 */
	private void encryptThenSign(final InputStream sourceInputStream, final OutputStream targetOutputStream) throws IOException, PGPException {
		assert this.encryptKey != null;
		assert this.signPublicKey != null;

		// signature
		final PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
				new JcaPGPContentSignerBuilder(this.signPublicKey.getAlgorithm(), this.hashAlgorithm).setProvider(BC));

		signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, this.signPrivateKey);

		final Iterator<?> it = this.signPublicKey.getUserIDs();
		// Just the first one!
		if (it.hasNext()) {
			final PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
			final String userId = (String) it.next();
			spGen.setSignerUserID(false, userId);
			signatureGenerator.setHashedSubpackets(spGen.generate());
		}

		// encryption
		final PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(
				new JcePGPDataEncryptorBuilder(this.symmetricKeyAlgorithm).setWithIntegrityPacket(this.withIntegrityCheck).setSecureRandom(new SecureRandom())
						.setProvider(BC));
		try {
			encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(this.encryptKey).setProvider(BC));

			try (OutputStream encryptedOut = encryptedDataGenerator.open(targetOutputStream, new byte[BUFFER_SIZE])) {

				signatureGenerator.generateOnePassVersion(false).encode(encryptedOut);

				// Create the Literal Data generator output stream
				final PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
				try {
					// create output stream
					try (final OutputStream literalOut = literalDataGenerator
							.open(encryptedOut, PGPLiteralData.BINARY, EMBEDDED_FILENAME, new Date(), new byte[BUFFER_SIZE])) {

						// read input file and write to target out stream using a buffer
						final byte[] buf = new byte[BUFFER_SIZE];
						int len;
						while ((len = sourceInputStream.read(buf, 0, buf.length)) > 0) {
							literalOut.write(buf, 0, len);
							signatureGenerator.update(buf, 0, len);
						}
					}
				} finally {
					literalDataGenerator.close();
				}

				signatureGenerator.generate().encode(encryptedOut);
			}
		} finally {
			encryptedDataGenerator.close();
		}
	}

	/**
	 * The data will be compressed first, then encrypted.
	 */
	private void encrypt(final InputStream sourceInputStream, final OutputStream targetOutputStream) throws IOException, PGPException {
		assert this.encryptKey != null;

		// encryption
		final PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(
				new JcePGPDataEncryptorBuilder(this.symmetricKeyAlgorithm).setWithIntegrityPacket(this.withIntegrityCheck).setSecureRandom(new SecureRandom())
						.setProvider(BC));
		try {
			encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(this.encryptKey).setProvider(BC));

			try (OutputStream encryptedOut = encryptedDataGenerator.open(targetOutputStream, new byte[BUFFER_SIZE])) {

				// compression
				final PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(this.compressionAlgorithm);
				try {
					try (OutputStream compressedOut = compressedDataGenerator.open(encryptedOut)) {

						// Create the Literal Data generator output stream
						final PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
						try {
							// create output stream
							try (final OutputStream literalOut = literalDataGenerator
									.open(compressedOut, PGPLiteralData.BINARY, EMBEDDED_FILENAME, new Date(), new byte[BUFFER_SIZE])) {

								// read input file and write to target out stream using a buffer
								final byte[] buf = new byte[BUFFER_SIZE];
								int len;
								while ((len = sourceInputStream.read(buf, 0, buf.length)) > 0) {
									literalOut.write(buf, 0, len);
								}
							}
						} finally {
							literalDataGenerator.close();
						}
					}
				} finally {
					compressedDataGenerator.close();
				}
			}
		} finally {
			encryptedDataGenerator.close();
		}
	}
}