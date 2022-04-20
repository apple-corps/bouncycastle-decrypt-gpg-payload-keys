package com.example;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;

public final class DecryptionService {
    public static void initialize() throws Exception {
        initializeSecurityProviders();

        DecryptionService ds = new DecryptionService();
        System.out.println(ds.decrypt(DecryptionService.class.getClassLoader().getResourceAsStream("launch-docker.sh.gpg"),"Arity2022"));
    }

    public static void initializeSecurityProviders() {

        // Add the Bouncy Castle security Provider to the JVM
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Encrypts a cleared message {@link String} using the classpath PGPPublicKey using
     * {@link ArmoredOutputStream} to further protect the encrypted message.
     *
     * @param message {@link String}
     * @return Encrypted String with, or without, armoring
     * @throws UnsupportedOperationException is thrown if the {@link PGPEncryptedDataGenerator} could not be initialized
     *                             from the provided PGPPublicKey or if the encoded message {@link OutputStream}
     *                             could not be opened
     */
    public String encrypt(String message) throws UnsupportedOperationException {

        /*
         * Initialize an OutputStream or ArmoredOutputStream for the encrypted message based on the armor
         * function input
         */
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        OutputStream armoredOutputStream = byteArrayOutputStream;
        armoredOutputStream = new ArmoredOutputStream(armoredOutputStream);

        // Initialize and configure the encryption generator using the provided PGPPublicKey
        PGPEncryptedDataGenerator pgpEncryptedDataGenerator = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                        .setSecureRandom(new SecureRandom())
                        .setProvider("BC"));

        pgpEncryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(getPublicKey())
                .setProvider("BC"));

        // Convert message String to byte[] using standard UTF-8
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        // Open the PGPEncryptedDataGenerator from the ArmoredOutputStream initialized to the message body length
        OutputStream encryptedOutputStream;
        try {
            encryptedOutputStream = pgpEncryptedDataGenerator.open(armoredOutputStream, messageBytes.length);
        } catch (IOException | PGPException e) {
            throw new UnsupportedOperationException("Could not open an OutputStream from the PGPEncryptedDataGenerator " +
                    "using the provided message body", e);
        }

        // Write the encrypted message to the encryptedOutputStream
        try {
            encryptedOutputStream.write(messageBytes);
        } catch (IOException e) {
            throw new UnsupportedOperationException("Could not write the message body to the encrypted OutputStream", e);
        } finally {

            // Close the encrypted message OutputStream
            try {
                encryptedOutputStream.close();
            } catch (IOException e) {
                // TODO: Log this
            }

            // Close the ArmoredOutputStream
            try {
                armoredOutputStream.close();
            } catch (IOException e) {
                // TODO: Log this
            }
        }

        // Return the encrypted message OutputStream to a String
        return byteArrayOutputStream.toString();
    }

    /**
     * Decrypts an encrypted message {@link String} using the {@link PGPSecretKey} on the classpath and its
     * password {@link String}
     *
     * @param encryptedStream {@link InputStream}
     * @param password         {@link String}
     * @return String
     * @throws UnsupportedOperationException is thrown if an encrypted message InputStream cannot be initialized from the
     *                             encryptedMessage {@link String}, if the PGPEncryptedDataList from that stream
     *                             contains no data, or if the password {@link String} for the
     *                             {@link PGPSecretKey} is incorrect
     */
    public String decrypt(InputStream encryptedStream, String password) throws UnsupportedOperationException {

        // Convert the encrypted String into an InputStream
        InputStream decoderStream;
        try {
            decoderStream = PGPUtil.getDecoderStream(encryptedStream);
        } catch (IOException e) {
            throw new UnsupportedOperationException("Could not initialize the DecoderStream", e);
        }

        // Retrieve the PGPEncryptedDataList from the encryptedStream
        JcaPGPObjectFactory jcaPGPObjectFactory = new JcaPGPObjectFactory(decoderStream);
        PGPEncryptedDataList pgpEncryptedDataList;

        /*
         * Evaluate the first object for a leading PGP marker packet and then return the encrypted
         * message body as a PGPEncryptedDataList
         */
        try {
            Object nextDataObject = jcaPGPObjectFactory.nextObject();
            if (nextDataObject instanceof PGPEncryptedDataList) {
                pgpEncryptedDataList = (PGPEncryptedDataList) nextDataObject;
            } else {
                pgpEncryptedDataList = (PGPEncryptedDataList) jcaPGPObjectFactory.nextObject();
            }
        } catch (IOException e) {
            throw new UnsupportedOperationException("Could not retrieve the encrupted message body", e);
        }

        // Retrieve the public key encrypted data from the encrypted message body
        PGPPublicKeyEncryptedData pgpPublicKeyEncryptedData =
                (PGPPublicKeyEncryptedData) pgpEncryptedDataList.getEncryptedDataObjects().next();

        // Use the PGPPublicKeyEncryptedData and Secret Key password to decrypt the encoded message
        InputStream decryptedInputStream;
        try {
            decryptedInputStream =
                    pgpPublicKeyEncryptedData.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder()
                            .setProvider("BC")
                            .build(getPrivateKey(getSecretKey1(), password)));
        } catch (PGPException e) {
            throw new UnsupportedOperationException("Could not decrypt the encoded message from the application " +
                    "Secret Key or the embedded Private Key", e);
        }

        // Convert the InputStream of the decrypted message to a String
        try {
            return IOUtils.toString(decryptedInputStream, StandardCharsets.UTF_8.name());
        } catch (IOException e) {
            throw new UnsupportedOperationException("Could not convert the decrypted InputStream to a UTF-8 String", e);
        }
    }


    private PGPSecretKey getSecretKey1() throws PGPException {
        long id = getPublicKey().getKeyID();
        InputStream secretKeyInputStream;
        try {
            secretKeyInputStream = DecryptionService.class.getClassLoader().getResourceAsStream("colin_secret");
        } catch (Exception e) {
            throw new UnsupportedOperationException("Could not retrieve the PGP Secret Key from the classpath", e);
        }
    
        // Load PGPSecretKey FileInputStream into the PGPSecretKeyRingCollection
        PGPSecretKeyRingCollection pgpSec;
        try {
            pgpSec = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(secretKeyInputStream), new JcaKeyFingerprintCalculator());
        } catch (IOException | PGPException e) {
            throw new UnsupportedOperationException("Could not initialize the PGPSecretKeyRingCollection", e);
        }
    
        return pgpSec.getSecretKey(id);
    
    
    }
    
    /**
     * Helper method for retrieving the {@link PGPPublicKey} from the application classpath.
     *
     * @return PGPPublicKey
     * @throws UnsupportedOperationException is thrown in the event that the PGP Public Key file does not contain a
     *                             Public Key or if the Public Key cannot be located on the file system
     */
    private PGPPublicKey getPublicKey() throws UnsupportedOperationException {
        InputStream publicKeyInputStream;
        // Read Public Key from the fInputStream pubKey;
        try {
            publicKeyInputStream = DecryptionService.class.getClassLoader().getResourceAsStream("colin_pub");
        } catch (Exception e) {
            throw new UnsupportedOperationException("Could not retrieve the PGP Public Key from the file system", e);
        }

        // Load PGPPublicKey FileInputStream into the PGPPublicKeyRingCollection
        PGPPublicKeyRingCollection pgpPub;
        try {
            pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(publicKeyInputStream),
                    new JcaKeyFingerprintCalculator());
        } catch (IOException | PGPException e) {
            throw new UnsupportedOperationException("Could not initialize the PGPPublicKeyRingCollection", e);
        }


        // Retrieve Public Key and evaluate if for the encryption key
        Iterator<PGPPublicKeyRing> keyRingIter = pgpPub.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPPublicKeyRing keyRing = keyRingIter.next();

            Iterator<PGPPublicKey> keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext()) {
                PGPPublicKey key = keyIter.next();

                if (key.isEncryptionKey()) {
                    return key;
                }
            }
        }

        throw new UnsupportedOperationException("The application PGPPublicKey is not an allowable encryption key");
    }

    /**
     * Helper method for retrieving the signing key {@link PGPSecretKey} from the classpath.
     *
     * @return Signing key {@link PGPSecretKey}
     * @throws UnsupportedOperationException is thrown if the Secret Key is not a signing key or if the Secret Key file
     *                             could not be located on the file system
     */
    private PGPSecretKey getSecretKey() throws UnsupportedOperationException {

        // Retrieve the application PGP secret key file from the classpath
        InputStream secretKeyInputStream;
        try {
            secretKeyInputStream = DecryptionService.class.getClassLoader().getResourceAsStream("colin_secret");
        } catch (Exception e) {
            throw new UnsupportedOperationException("Could not retrieve the PGP Secret Key from the classpath", e);
        }

        // Read Secret Key file and load it into a PGPPublicKeyRingCollection for evaluation

        // Load PGPSecretKey FileInputStream into the PGPSecretKeyRingCollection
        PGPSecretKeyRingCollection pgpSec;
        try {
            pgpSec = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(secretKeyInputStream), new JcaKeyFingerprintCalculator());
        } catch (IOException | PGPException e) {
            throw new UnsupportedOperationException("Could not initialize the PGPSecretKeyRingCollection", e);
        }

        // Retrieve signing Secret Key
        Iterator<PGPSecretKeyRing> secretKeyRingIterator = pgpSec.getKeyRings();
        while (secretKeyRingIterator.hasNext()) {
            PGPSecretKeyRing keyRing = secretKeyRingIterator.next();

            Iterator<PGPSecretKey> keyIter = keyRing.getSecretKeys();
            while (keyIter.hasNext()) {
                PGPSecretKey key = keyIter.next();

                if (key.isSigningKey()) {
                    return key;
                }
            }
        }

        throw new UnsupportedOperationException("The application PGPSecretKey is not a signing key");
    }

    /**
     * Retrieves the {@link PGPPrivateKey} from the provided {@link PGPSecretKey} and its password.
     *
     * @param secretKey {@link PGPSecretKey}
     * @param password  {@link String}
     * @return PGPPrivateKey
     * @throws UnsupportedOperationException is thrown in the event that the password for the {@link PGPSecretKey}
     *                             is incorrect
     */
    private PGPPrivateKey getPrivateKey(PGPSecretKey secretKey, String password) throws UnsupportedOperationException {

        PBESecretKeyDecryptor decryptorFactory = new BcPBESecretKeyDecryptorBuilder(
                new BcPGPDigestCalculatorProvider()).build(password.toCharArray());

        try {
            return secretKey.extractPrivateKey(decryptorFactory);
        } catch (PGPException e) {
            throw new UnsupportedOperationException("Could not extract the Private Key from the application Secret Key", e);
        }
    }
}
