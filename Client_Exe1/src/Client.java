//Γεώργιος Ζέρβας icsd13055
//Νικόλαος Φουρτούνης icsd13195
//Παύλος Σκούπρας icsd13171

import static com.sun.org.apache.xalan.internal.lib.ExsltDatetime.date;
import static com.sun.org.apache.xalan.internal.lib.ExsltDatetime.date;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import org.bouncycastle.*;
import org.bouncycastle.openssl.PEMReader;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.InterruptedIOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import net.i2p.I2PException;
import net.i2p.client.I2PSession;
import net.i2p.client.streaming.I2PSocket;
import net.i2p.client.streaming.I2PSocketManager;
import net.i2p.client.streaming.I2PSocketManagerFactory;

import net.i2p.data.DataFormatException;
import net.i2p.data.Destination;


public class Client implements Serializable {

    static ObjectOutputStream out;
    static ObjectInputStream in;

    public static void main(String[] args) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, InvalidKeyException {

        I2PSocketManager manager = I2PSocketManagerFactory.createManager();
        I2PSession session = manager.getSession();
        System.out.println("This is Server Destination in form Base64: \n"
                + session.getMyDestination().toBase64() + "\n");
        System.out.println("ENTER THE DESTINATION OF SERVER:");
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        String destinationString;
        try {
            destinationString = br.readLine();
        } catch (IOException ex) {
            System.out.println("Failed to get a Destination string.");
            return;
        }
        Destination destination;
        try {
            destination = new Destination(destinationString);
        } catch (DataFormatException ex) {
            System.out.println("Destination string incorrectly formatted." + "\n");
            return;
        }

        I2PSocket socket;

        try {
            socket = manager.connect(destination);
            System.out.println();
            System.out.println("We have connection with the server." + "\n");
        } catch (I2PException ex) {
            System.out.println("General I2P exception occurred!");
            return;
        } catch (ConnectException ex) {
            System.out.println("Failed to connect!");
            return;
        } catch (NoRouteToHostException ex) {
            System.out.println("Couldn't find host!");
            return;
        } catch (InterruptedIOException ex) {
            System.out.println("Sending/receiving was interrupted!");
            return;
        }

        try {
            //******************************************************************************
            //*********************************SET VARIABLES********************************
            //******************************************************************************
            byte[] server_cookie;
            byte[] client_cookie;
            String cookie_message;

            String suite1_choosen;
            String suite2_choosen;
            X509Certificate certificate;

            String[] integrity_algo = {"MD5", "SHA-1"};
            String[] summetry_algo = {"AES", "BlowFish"};

            out = new ObjectOutputStream((socket.getOutputStream()));
            in = new ObjectInputStream((socket.getInputStream()));

            //******************************************************************************
            //*************************SEND TO SERVER THE FIRST MESSAGE*********************
            //******************************************************************************
            Message message_from_server = new Message("Hello I2P!");
            out.writeObject(message_from_server);
            out.flush();

            //******************************************************************************
            //***********************READ FIRST MESSAGE FROM SERVER ****************************
            //******************************************************************************
            message_from_server = (Message) in.readObject();

            cookie_message = message_from_server.getmessage();

            if (cookie_message.equals("cookie-server")) {

                server_cookie = message_from_server.getcookie1();
                System.out.println("Server cookie was recieved.");
                System.out.println(convertToHex(server_cookie) + "\n");

                //******************************************************************************
                //*************************CREATE A COOKIE FOR CLIENT***************************
                //******************************************************************************
                SecureRandom random = new SecureRandom();
                client_cookie = new byte[8];
                random.nextBytes(client_cookie);
                System.out.println("Cookie Client was created.");
                System.out.println(convertToHex(client_cookie) + "\n");

                out.writeObject(new Message(server_cookie, client_cookie, integrity_algo, summetry_algo));
                out.flush();

                System.out.println("Cookie-Client was created and sent with the available suites to the client.\n");

                //******************************************************************************
                //************RECIEVE A MESSAGE FROM SERVER WITH HIS AVAILABLE SUITES***********
                //******************************************************************************
                message_from_server = (Message) in.readObject();
                suite1_choosen = message_from_server.getsuite1();
                suite2_choosen = message_from_server.getsuite2();

                //******************************************************************************
                //****************************THE CERTIFICATE***********************************
                //******************************************************************************
                certificate = (X509Certificate) message_from_server.getcerti();
                Date date = new Date();
                Date cert_date = certificate.getNotAfter();

                System.out.println("The server choose: " + suite1_choosen + " and " + suite2_choosen + "\n");

                //******************************************************************************
                //************************CHECK IF CERTIFICATE IS VALID*************************
                //******************************************************************************
                if (isSelfSigned(certificate) && date.before(cert_date)) {

                    System.out.println("Certiicate is valid.\n");

                    //******************************************************************************
                    //*****************************CREATE RN****************************************
                    //******************************************************************************
                    SecureRandom random_rn = new SecureRandom();
                    byte[] rn_bytes = new byte[16];
                    random.nextBytes(rn_bytes);
                    System.out.println("The RN is: " + convertToHex(rn_bytes) + "\n");

                    //******************************************************************************
                    //*********CREATE THE DIGEST FROM RN-CLIENT-COOKIE AND SERVER-COOKIE************
                    //******************************************************************************
                    byte[] key_digest = createDigestForKeys(rn_bytes, client_cookie, server_cookie);
                    System.out.println("The DIGEST of two keys was created.\n");

                    //******************************************************************************
                    //**********************KEYS FOR INTEGRITY AND CONFIDENTIALITY******************
                    //******************************************************************************
                    byte[] confidentiality_key = new byte[16];
                    System.arraycopy(key_digest, 0, confidentiality_key, 0, 16);

                    byte[] integrity_key = new byte[16];
                    System.arraycopy(key_digest, 16, integrity_key, 0, 16);

                    System.out.println("The key for confidentiality is: " + convertToHex(confidentiality_key));
                    System.out.println("The key for integrity is: " + convertToHex(integrity_key) + "\n");

                    //******************************************************************************
                    //**********************GET PUBLIC KEY AND ENCRYPT IT WITH RN*******************
                    //******************************************************************************
                    PublicKey public_key = certificate.getPublicKey();
                    System.out.println("INFORMATION ABOUT PUBLIC KEY");
                    System.out.println(public_key.toString() + "\n");

                    SealedObject encrypt_rn = null;
                    encrypt_rn = Encrypt_RN(public_key, rn_bytes, "RSA");
                    System.out.println("The encryption for RN is done.\n");

                    //******************************************************************************
                    //*******JOIN TWO SUITES AND ENCRYPTED WITH MD5 ALGORITHM TO CREATE HMAC********
                    //******************************************************************************
                    String final_suites = suite1_choosen + "" + suite2_choosen;
                    String hmac = hmac(confidentiality_key, final_suites);
                    System.out.println("HMAC was created." + "\n");

                    //******************************************************************************
                    //********************SEND TO SERVER THOSE TWO ENCRYPTED THINGS*****************
                    //******************************************************************************
                    out.writeObject(new Message("HMAC and RN", hmac, encrypt_rn));
                    out.flush();
                    System.out.println("HMAC and encrypted RN was sent by the server." + "\n");

                    //******************************************************************************
                    //********************RECIEVE ACKNOWLEDGEMENT FROM SERVER***********************
                    //******************************************************************************
                    message_from_server = (Message) in.readObject();
                    SealedObject ackno = message_from_server.getdigestrn();
                    SecretKey ack_key = new SecretKeySpec(confidentiality_key, 0, confidentiality_key.length, "AES");
                    String ack_message = AES_Decrypt_Algorithm(ack_key, ackno);

                    System.out.println("The server sent the message: " + ack_message + "\n");

                } else {
                    socket.close();
                    System.out.println("The certificate isn't valid.");
                }

            }

            socket.close();
        } catch (IOException ex) {
            System.out.println("Error occurred while sending/receiving!");
        }
    }

    //******************************************************************************
    //****************************ALGORITHMS FOR INTEGRITY**************************
    //******************************************************************************
    private static String MD5_Algorithm(String yourString)
            throws UnsupportedEncodingException, NoSuchAlgorithmException {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] messageDigest = md.digest(yourString.getBytes());
            BigInteger number = new BigInteger(1, messageDigest);
            String hashtext = number.toString(16);
            // Now we need to zero pad it if you actually want the full 32 chars.
            while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }
            return hashtext;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);

        }
    }

    private static String SHA1_Algorithm(String rn_string, String public_key)
            throws NoSuchAlgorithmException, UnsupportedEncodingException {

        MessageDigest digest = MessageDigest.getInstance("SHA-1");

        digest.update(rn_string.getBytes());
        byte[] bytes = digest.digest(public_key.getBytes());
        return convertToHex(bytes);

    }

    //***************************************************************************
    //*******************ALGORITHMS FOR SYMMETRIC CRYPTOGRAPHY*******************
    //***************************************************************************
    private static SealedObject AES_Encrypt_Algorithm(Key encryptionKey, byte[] dataToEncrypt) {

        Cipher cipher;
        SealedObject sealed = null;

        try {
            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
            sealed = new SealedObject(dataToEncrypt, cipher);

        } catch (NoSuchPaddingException | InvalidKeyException | IOException |
                IllegalBlockSizeException | NoSuchAlgorithmException ex) {
        }
        return sealed;
    }

    private static String AES_Decrypt_Algorithm(Key decryptionKey, SealedObject dataToDencrypt) {

        Cipher cipher;
        String decryptedTrans = null;

        try {
            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, decryptionKey);
            decryptedTrans = (String) dataToDencrypt.getObject(cipher);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException |
                InvalidKeyException | IOException | ClassNotFoundException | BadPaddingException | IllegalBlockSizeException ex) {
        }
        return decryptedTrans;
    }

    private static String BlowFish_Decrypt_Algorithm(Key decryptionKey, SealedObject dataToDencrypt)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException,
            ClassNotFoundException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance("Blowfish");
        cipher.init(Cipher.DECRYPT_MODE, decryptionKey);
        String decrypted_string = (String) dataToDencrypt.getObject(cipher);
        return decrypted_string;
    }

    private static SealedObject BlowFish_Encrypt_Algorithm(Key decryptionKey, byte[] dataToEncrypt)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException,
            ClassNotFoundException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance("Blowfish");
        cipher.init(Cipher.ENCRYPT_MODE, decryptionKey);
        SealedObject encrypted = new SealedObject(dataToEncrypt, cipher);

        return encrypted;
    }

    //******************************************************************************
    //******************FUNCTION TO CONVERT BYTES[] TO STRING***********************
    //******************************************************************************
    private static String convertToHex(byte[] data) {
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < data.length; i++) {
            int halfbyte = (data[i] >>> 4) & 0x0F;
            int two_halfs = 0;
            do {
                if ((0 <= halfbyte) && (halfbyte <= 9)) {
                    buf.append((char) ('0' + halfbyte));
                } else {
                    buf.append((char) ('a' + (halfbyte - 10)));
                }
                halfbyte = data[i] & 0x0F;
            } while (two_halfs++ < 1);
        }
        return buf.toString();
    }

    //******************************************************************************
    //*******FUNCTION TO ENCRYPT THE DATA WITH THE SIMILAR ALGORITHM****************
    //******************************************************************************
    private static SealedObject Encrypt_RN(PublicKey encryptionKey, byte[] byte_rn, String algorithm) {

        Cipher cipher;
        SealedObject encryptedRN = null;

        try {
            cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
            encryptedRN = new SealedObject(byte_rn, cipher);

        } catch (NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | NoSuchAlgorithmException | IOException ex) {
        }

        return encryptedRN;

    }

    //******************************************************************************
    //*******************WE CHECK IF VERIFICATION IS VALID**************************
    //******************************************************************************
    private static boolean isSelfSigned(X509Certificate cert)
            throws CertificateException, NoSuchAlgorithmException,
            NoSuchProviderException {
        try {
            // Try to verify certificate signature with its own public key
            PublicKey key = cert.getPublicKey();
            cert.verify(key);
            return true;
        } catch (SignatureException sigEx) {
            // Invalid signature --> not self-signed
            return false;
        } catch (InvalidKeyException keyEx) {
            // Invalid key --> not self-signed
            return false;
        }
    }

    private static String hmac(byte[] integrity, String data) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException {

        byte[] bytes;
        String sEncodedString = null;

        Mac mac = Mac.getInstance("HmacMD5");
        SecretKeySpec secret_key = new SecretKeySpec(integrity, "HmacMD5");
        mac.init(secret_key);
        mac.update(data.getBytes());

        bytes = mac.doFinal(data.getBytes());

        StringBuffer hash = new StringBuffer();
        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(0xFF & bytes[i]);
            if (hex.length() == 1) {
                hash.append('0');
            }
            hash.append(hex);
        }

        sEncodedString = hash.toString();
        return sEncodedString;

    }

    //******************************************************************************
    //*******************FUNCTION TO CREATE THE DIGEST FOR KEYS*********************
    //******************************************************************************
    private static byte[] createDigestForKeys(byte[] rn_byte, byte[] client_cookie, byte[] server_cookie)
            throws NoSuchAlgorithmException {

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(client_cookie);
        byte[] temp_bytes = digest.digest(server_cookie);

        //THEN THE TEMP_BYTE[] WITH THE BYTE_RN
        digest.update(temp_bytes);
        byte[] final_digest = digest.digest(rn_byte);
        return final_digest;
    }

}
