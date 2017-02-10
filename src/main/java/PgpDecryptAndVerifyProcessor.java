

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Iterator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPMarker;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;


/**
 * The PGP Decrypt and Verify processor
 */
public class PgpDecryptAndVerifyProcessor {

	private static int BUFFER_SIZE = 4096;
	private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

	private final PGPSecretKeyRing decryptKeyRing;
	private final String passphraseForDecrypt;
	private final PGPPublicKeyRing verifyKeyRing;

	public PgpDecryptAndVerifyProcessor(final PGPSecretKeyRing decryptKeyRing, final String passphraseForDecrypt, final PGPPublicKeyRing verifyKeyRing) throws PGPException {
		assert decryptKeyRing != null || verifyKeyRing != null;

		this.decryptKeyRing = decryptKeyRing;
		this.passphraseForDecrypt = passphraseForDecrypt;
		this.verifyKeyRing = verifyKeyRing;
		
		// verify the passphrase is valid
		this.decryptKeyRing.getSecretKey().extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider(BC).build(passphraseForDecrypt.toCharArray()));
	}

	/**
	 * Process decrypt or/and verify operation
	 *
	 * @param in the input stream
	 * @param out the output stream
	 * @throws IOException thrown if there is an error with IO stream
	 * @throws PGPException thrown if there is an error with PGP operation
	 */
	public void process(final InputStream in, final OutputStream out) throws IOException, PGPException {

		final PGPObjectFactory objectFactory = new JcaPGPObjectFactory(PGPUtil.getDecoderStream(in));

		final PgpDataTracker tracker = new PgpDataTracker();
		visit(tracker, objectFactory);

		final PGPLiteralData literalData = tracker.literalData;
		if (literalData == null) {
			throw new PGPException("There is no literal data available."); //$NON-NLS-1$
		}

		try (InputStream literalIn = literalData.getInputStream()) {
			writeContent(tracker, literalIn, out);
		}

		if (tracker.onePassSignature != null) {
			final PGPSignatureList signitureList = (PGPSignatureList) tracker.literalFactory.nextObject();
			if (!tracker.onePassSignature.verify(signitureList.get(0))) {
				throw new PGPException("Signature verification failed."); //$NON-NLS-1$
			}
		}

		final PGPEncryptedData encryptedData = tracker.encryptedData;
		if (encryptedData != null) {
			if (encryptedData.isIntegrityProtected() && !encryptedData.verify()) {
				throw new PGPException("Integrity check failed."); //$NON-NLS-1$
			}
		}
	}

	/**
	 * Extract compression pack out
	 *
	 * @param data compression pack from PGP message
	 * @return the next PGP pack for processing
	 * @throws PGPException thrown if any error occurs from BC internally
	 */
	private PGPObjectFactory doDecompression(final PGPCompressedData data) throws PGPException {
		return new JcaPGPObjectFactory(data.getDataStream());
	}

	/**
	 * Match a signature to the given verify keyring. Add the matched signature
	 * to the tracker.
	 *
	 * @param tracker the PGP data tracker
	 * @param signatureList signature list pack from PGP message
	 * @throws PGPException thrown if cannot find a match or any error occurs
	 *             from BC internally
	 */
	private void doSignature(final PgpDataTracker tracker, final PGPOnePassSignatureList signatureList) throws PGPException {

		PGPOnePassSignature signature = null;
		PGPPublicKey matchedVerifyKey = null;

		final Iterator<PGPOnePassSignature> it = signatureList.iterator();
		while (it.hasNext() && matchedVerifyKey == null) {
			signature = it.next();

			if (this.verifyKeyRing == null) {
				throw new PGPException("Verify keyring is not specified."); //$NON-NLS-1$
			}
		
			matchedVerifyKey = this.verifyKeyRing.getPublicKey(signature.getKeyID());
		}

		if (signature == null || matchedVerifyKey == null) {
			throw new PGPException("There are no signatures which can be verified by the given keyring."); //$NON-NLS-1$
		}

		signature.init(new JcaPGPContentVerifierBuilderProvider().setProvider(BC), matchedVerifyKey);
		tracker.addOnePassSignature(signature);
	}

	/**
	 * Match an encrypted pack to the given decrypt keyring. Add the matched
	 * encrypted pack to the tracker.
	 *
	 * @param tracker the PGP data tracker
	 * @param data encrypted data list
	 * @return the next PGP pack for processing
	 * @throws PGPException thrown if cannot find a match or any error occurs
	 *             from BC internally
	 */
	private PGPObjectFactory doDecryption(final PgpDataTracker tracker, final PGPEncryptedDataList data) throws PGPException {

		PGPPublicKeyEncryptedData encrytedData = null;
		PGPSecretKey matchedDecryptKey = null;

		final Iterator<?> it = data.getEncryptedDataObjects();
		while (it.hasNext() && matchedDecryptKey == null) {
			encrytedData = (PGPPublicKeyEncryptedData) it.next();

			if (this.decryptKeyRing == null) {
				throw new PGPException("Decrypt keyring is not specified."); //$NON-NLS-1$
			}

			matchedDecryptKey = this.decryptKeyRing.getSecretKey(encrytedData.getKeyID());
		}

		if (encrytedData == null || matchedDecryptKey == null) {
			throw new PGPException("There is no encrypted data which can be decrypted by the given keyring."); //$NON-NLS-1$
		}

		tracker.addEncryptedData(encrytedData);

		// extract the private key from secret key
		PGPPrivateKey theDecryptKey = matchedDecryptKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider(BC).build(passphraseForDecrypt.toCharArray()));
		
		final InputStream stream = encrytedData.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider(BC).build(theDecryptKey));
		return new JcaPGPObjectFactory(stream);
	}

	/*
	 * Recursively visit all the objects till found the literal data pack
	 */
	private void visit(final PgpDataTracker tracker, final PGPObjectFactory objectFactory) throws PGPException {

		final Iterator<?> iterator = objectFactory.iterator();
		while (!tracker.foundLiteralData() && iterator.hasNext()) {
			final Object obj = iterator.next();

			if (obj instanceof PGPMarker) {
				// It's a PGP marker, do nothing
			} else if (obj instanceof PGPCompressedData) {
				visit(tracker, doDecompression((PGPCompressedData) obj));
			} else if (obj instanceof PGPOnePassSignatureList) {
				doSignature(tracker, (PGPOnePassSignatureList) obj);
			} else if (obj instanceof PGPEncryptedDataList) {
				final PGPObjectFactory newFactory = doDecryption(tracker, (PGPEncryptedDataList) obj);
				visit(tracker, newFactory);
			} else if (obj instanceof PGPLiteralData) {
				tracker.addLiteralData((PGPLiteralData) obj);
				// literal factory will be used to retrieve the signature list after write literal
				tracker.addLiteralFactory(objectFactory);
			}
		}
	}

	/**
	 * Write the literal data to the output stream.
	 */
	private void writeContent(final PgpDataTracker walker, final InputStream in, final OutputStream out) throws IOException {
		int length;
		final byte[] buffer = new byte[BUFFER_SIZE];
		while ((length = in.read(buffer)) > 0) {
			if (walker.onePassSignature != null) {
				// update the signature
				walker.onePassSignature.update(buffer, 0, length);
			}
			// write the content
			out.write(buffer, 0, length);
		}
	}

	/**
	 * Track all the data and signatures of a PGP data object, keep a reference
	 * of each object
	 */
	private class PgpDataTracker {

		private PGPEncryptedData encryptedData;
		private PGPLiteralData literalData;
		private PGPOnePassSignature onePassSignature;
		private PGPObjectFactory literalFactory;

		void addEncryptedData(final PGPEncryptedData data) {
			this.encryptedData = data;
		}

		void addLiteralData(final PGPLiteralData data) {
			this.literalData = data;
		}

		void addOnePassSignature(final PGPOnePassSignature signature) {
			this.onePassSignature = signature;
		}

		void addLiteralFactory(final PGPObjectFactory factory) {
			this.literalFactory = factory;
		}

		boolean foundLiteralData() {
			return this.literalData != null;
		}
	}
}