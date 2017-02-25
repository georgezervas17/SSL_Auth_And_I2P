//Γεώργιος Ζέρβας icsd13055
//Νικόλαος Φουρτούνης icsd13195
//Παύλος Σκούπρας icsd13171

import java.io.Serializable;
import java.security.cert.X509Certificate;
import javax.crypto.SealedObject;

public class Message implements Serializable {

    String message;
    String digest_md5;
    SealedObject digest_rn;
    X509Certificate certificate;
    byte[] cookie1;
    byte[] cookie2;
    String[] integrity;
    String[] symmetric;
    String suite1;
    String suite2;

    Message() {
    }

    Message(String p_message) {
        message = p_message;
    }

    Message(String p_message, String p_digest_md5, SealedObject p_digest_rn) {
        message = p_message;
        digest_md5 = p_digest_md5;
        digest_rn = p_digest_rn;

    }

    Message(String p_message, byte[] p_cookie1) {
        message = p_message;
        cookie1 = p_cookie1;
    }

    Message(SealedObject p_digest) {
        digest_rn = p_digest;
    }

    Message(String p_suite1, String p_suite2, X509Certificate p_certi) {
        suite1 = p_suite1;
        suite2 = p_suite2;
        certificate = p_certi;
    }

    Message(X509Certificate p_certi, byte[] p_cookie1, byte[] p_cookie2) {
        certificate = p_certi;
        cookie1 = p_cookie1;
        cookie2 = p_cookie2;

    }

    Message(byte[] p_cookie1, byte[] p_cookie2, String[] p_inte, String[] p_summetry) {
        cookie1 = p_cookie1;
        cookie2 = p_cookie2;
        integrity = p_inte;
        symmetric = p_summetry;

    }

    String getmessage() {
        return message;
    }

    byte[] getcookie1() {
        return cookie1;
    }

    byte[] getcookie2() {
        return cookie2;
    }

    String getsuite1() {
        return suite1;

    }

    String getsuite2() {
        return suite2;
    }

    String[] getinte() {
        return integrity;
    }

    String[] getsummetry() {
        return symmetric;
    }

    String getmd5() {
        return digest_md5;
    }

    SealedObject getdigestrn() {
        return digest_rn;
    }

    X509Certificate getcerti() {
        return certificate;
    }
}
