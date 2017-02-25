//Γεώργιος Ζέρβας icsd13055
//Νικόλαος Φουρτούνης icsd13195
//Παύλος Σκούπρας icsd13171

import java.io.FileNotFoundException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import net.i2p.I2PException;
import net.i2p.client.streaming.I2PSocket;
import net.i2p.util.I2PThread;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.i2p.client.I2PSession;
import net.i2p.client.streaming.I2PServerSocket;
import net.i2p.client.streaming.I2PSocketManager;
import net.i2p.client.streaming.I2PSocketManagerFactory;
import java.nio.file.Files;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;

public class Server {

    static ObjectOutputStream out;
    static ObjectInputStream in;

    public static void main(String[] args) throws FileNotFoundException {
        Security.addProvider(new BouncyCastleProvider());
        
        I2PSocketManager manager = I2PSocketManagerFactory.createManager();
        I2PServerSocket serverSocket = manager.getServerSocket();
        I2PSession session = manager.getSession();
        System.out.println("This is Server Destination in form Base64: \n"
                + session.getMyDestination().toBase64() + "\n");

        //******************************************************************************
        //*************************CREATE A SOCKET FOR THE CLIENT***********************
        //******************************************************************************
        I2PThread t = new I2PThread(new ClientHandler(serverSocket));
        t.setName("clienthandler1");
        t.setDaemon(false);

        //******************************************************************************
        //*************************START RUN FUNCTION***********************
        //******************************************************************************
        t.start();
    }

    private static class ClientHandler extends Thread {

        public ClientHandler(I2PServerSocket socket) {
            this.socket = socket;
        }

        public void run() {

            Message message;
            try {
                //******************************************************************************
                //**************************ACCEPT THE SOCKET***********************************
                //******************************************************************************
                I2PSocket sock = this.socket.accept();

                in = new ObjectInputStream((sock.getInputStream()));
                out = new ObjectOutputStream((sock.getOutputStream()));

                byte[] client_cookie;
                byte[] server_cookie;
                String[] summetry_algo;
                String[] integrity_algo;
                String suite1 = null;
                String suite2 = null;

                String message_from_client;

                if (sock != null) {

                    //******************************************************************************
                    //***************RECIEVE A MESSAGE FROM CLIENT WITH HELLO***********************
                    //******************************************************************************
                    message = (Message) in.readObject();
                    message_from_client = message.getmessage();

                    if (message_from_client.equals("Hello I2P!")) {

                        System.out.println("Recieved from client: " + message_from_client + "\n");

                        //******************************************************************************
                        //***********CREATE COOKIE FOR SERVER AND SEND IT TO CLIENT*********************
                        //******************************************************************************
                        SecureRandom random = new SecureRandom();
                        server_cookie = new byte[8];
                        random.nextBytes(server_cookie);

                        out.writeObject(new Message("cookie-server", server_cookie));
                        out.flush();

                        System.out.println("Cookie-Server was created and sent to the client." + "\n");

                        //******************************************************************************
                        //**********RECIEVE A MESSAGE FROM CLIENT WITH HIS COOKIE AND HIS SUITES********
                        //******************************************************************************
                        message = (Message) in.readObject();
                        client_cookie = message.getcookie2();
                        integrity_algo = message.getinte();
                        summetry_algo = message.getsummetry();

                        System.out.println("Cookie client and available suites was recieved!" + "\n");

                        //******************************************************************************
                        //**********CHECK IF SERVER HAS THE SAME AVAILABLE SUITES WITH CLIENT***********
                        //******************************************************************************
                        for (int i = 0; i < integrity_algo.length; i++) {
                            if (integrity_algo[i].equals("MD5")) {
                                suite1 = integrity_algo[i];
                            }
                        }
                        for (int i = 0; i < summetry_algo.length; i++) {
                            if (summetry_algo[i].equals("AES")) {
                                suite2 = summetry_algo[i];
                            }
                        }

                        //******************************************************************************
                        //*****************IF SERVER HAS THE SAME SUITES THEN CONTINUE******************
                        //******************************************************************************
                        if (!suite1.equals(null) && !suite2.equals(null)) {

                            System.out.println("Server choose suites: " + suite1 + " and " + suite2 + "\n");

                            //******************************************************************************
                            //*************CALL THE FUNCTION BELOW TO LOAD THE CERTIFICATE******************
                            //******************************************************************************
                            X509Certificate cert = loadCertificate();

                            //******************************************************************************
                            //***************SEND TO CLIENT THE SUITES AND THE CERTIFICATE******************
                            //******************************************************************************
                            out.writeObject(new Message(suite1, suite2, cert));
                            out.flush();

                            System.out.println("The suites and the certificate has been sent." + "\n");

                            //******************************************************************************
                            //*************RECIEVE A MESSAGE FROM CLIENT WITH HMAC AND ENCRYPTED RN*********
                            //******************************************************************************
                            message = (Message) in.readObject();
                            String hmac_suites = message.getmd5();
                            SealedObject rn = message.getdigestrn();

                            //******************************************************************************
                            //******************LOAD THE PRIVATE KEY TO DECRYPT THE RN**********************
                            //******************************************************************************
                            File private_key_path = new File("C:\\keyout.der");
                            byte[] keyBytes = Files.readAllBytes(private_key_path.toPath());

                            //******************************************************************************
                            //**********************WE ENCODE THE PRIVATE KEY*******************************
                            //******************************************************************************
                            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
                            KeyFactory kf = KeyFactory.getInstance("RSA");
                            PrivateKey privkey = kf.generatePrivate(spec);

                            //******************************************************************************
                            //***************DECRYPT THE PRIVATE-KEY AND RN AND PRINT RN********************
                            //******************************************************************************
                            byte[] byte_rn = Decrypt_RN(privkey, rn, "RSA");
                            System.out.println("The RN is:" + convertToHex(byte_rn) + "\n");

                            byte[] keys_digest = createDigestForKeys(byte_rn, client_cookie, server_cookie);

                            byte[] confidentiality_key = new byte[16];
                            System.arraycopy(keys_digest, 0, confidentiality_key, 0, 16);

                            byte[] integrity_key = new byte[16];
                            System.arraycopy(keys_digest, 16, integrity_key, 0, 16);

                            System.out.println("The key for confidentiality key is: " + convertToHex(confidentiality_key));
                            System.out.println("The key for integrity key is: " + convertToHex(integrity_key) + "\n");

                            //******************************************************************************
                            //*************JOIN TWO SUITES AND HASHED WITH THE MD5 ALGORITHM****************
                            //******************************************************************************
                            String final_suites = suite1 + "" + suite2;
                            String server_suites1 = hmac(confidentiality_key, final_suites);

                            //******************************************************************************
                            //********WE COMPARE THE HMAC THAT WE RECIEVED WITH THAT WE HAS CREATED*********
                            //******************************************************************************                           
                            if (hmac_suites.equals(server_suites1)) {

                                System.out.println("The suites are the same!" + "\n");

                                //******************************************************************************
                                //**************************THE ACKNOWLEDGEMENT TO CLIENT***********************
                                //******************************************************************************
                                String ack = new String("The protocol was finished.");
                                SecretKey ack_key = new SecretKeySpec(confidentiality_key, 0, confidentiality_key.length, "AES");

                                SealedObject ackno = AES_Encrypt_Algorithm(ack_key, ack);

                                out.writeObject(new Message(ackno));
                                out.flush();

                                System.out.println("The acknowledgement has been sent." + "\n");
                            }

                            sock.close();
                        } else {
                            System.out.println("The server has different suites.");
                        }

                    } else {
                        System.out.println("The client doesn't sent the right message.");
                        sock.close();
                    }
                }
            } catch (I2PException ex) {
                System.out.println("General I2P exception!");
            } catch (ConnectException ex) {
                System.out.println("Error connecting!");
            } catch (SocketTimeoutException ex) {
                System.out.println("Timeout!");
            } catch (IOException ex) {
                System.out.println("General read/write-exception!");
            } catch (ClassNotFoundException ex) {
                Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
            } catch (CertificateException ex) {
                Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchProviderException ex) {
                Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
            } catch (SignatureException ex) {
                Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeySpecException ex) {
                Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        private I2PServerSocket socket;
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

    //******************************************************************************
    //***************ALGORITHM TO SYMMETRIC CRYPTOGRAPHY****************************
    //******************************************************************************
    public static SealedObject AES_Encrypt_Algorithm(Key encryptionKey, String dataToEncrypt) {

        Cipher cipher;
        SealedObject sealed = null;

        try {
            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
            sealed = new SealedObject(dataToEncrypt, cipher);

        } catch (NoSuchPaddingException | InvalidKeyException | IOException | IllegalBlockSizeException | NoSuchAlgorithmException ex) {

        }
        return sealed;
    }

    public static String AES_Decrypt_Algorithm(Key decryptionKey, SealedObject dataToDencrypt) {

        Cipher cipher;
        String decryptedTrans = null;

        try {
            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, decryptionKey);
            decryptedTrans = (String) dataToDencrypt.getObject(cipher);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IOException | ClassNotFoundException | BadPaddingException | IllegalBlockSizeException ex) {

        }
        return decryptedTrans;
    }

    //******************************************************************************
    //***************FUNCTION TO CONVERT BYTES[] TO STRING**************************
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
    //***************FUNCTION TO LOAD THE CERTIFICATE*******************************
    //******************************************************************************
    private static X509Certificate loadCertificate()
            throws FileNotFoundException, IOException, CertificateException,
            NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException,
            SignatureException {

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        FileReader fr = new FileReader("C:\\certificate.crt");
        PEMReader pemReader = new PEMReader(fr);
        X509Certificate cert = (X509Certificate) pemReader.readObject();
        PublicKey key = cert.getPublicKey();
        cert.verify(key);

        return cert;
    }

    //******************************************************************************
    //***************FUNCTION TO DECRYPT RN*****************************************
    //******************************************************************************
    public static byte[] Decrypt_RN(PrivateKey private_key, SealedObject dataToDecrypt, String algorithm) {
        Cipher cipher;
        byte[] decrypted = null;

        try {
            cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, private_key);
            decrypted = (byte[]) dataToDecrypt.getObject(cipher);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IOException | ClassNotFoundException | BadPaddingException | IllegalBlockSizeException ex) {
        }
        return decrypted;
    }

    //******************************************************************************
    //***********FUNCTION TO CREATE HMAC WITH MD5 ALGORITHM*************************
    //******************************************************************************
    private static String hmac(byte[] integrity, String data) throws NoSuchAlgorithmException, 
            InvalidKeyException, UnsupportedEncodingException {

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
    //***************FUNCTION TO CREATE DIGEST FOR KEYS*****************************
    //******************************************************************************
    public static byte[] createDigestForKeys(byte[] rn_byte, byte[] client_cookie, byte[] server_cookie) throws NoSuchAlgorithmException {

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(client_cookie);
        byte[] temp_bytes = digest.digest(server_cookie);

        digest.update(temp_bytes);
        byte[] final_digest = digest.digest(rn_byte);
        return final_digest;
    }
}
