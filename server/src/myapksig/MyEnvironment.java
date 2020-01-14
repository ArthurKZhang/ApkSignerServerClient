package myapksig;

import myapksig.internal.apk.v1.DigestAlgorithm;
import myapksig.internal.apk.v1.V1SchemeSigner;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

public class MyEnvironment {
    public static PrivateKey privateKey;
    public static List<X509Certificate> certs;
    public static PublicKey publicKey;
    public static DigestAlgorithm v1SignatureDigestAlgorithm;
    public static String v1SigBasename;

    public static void loadEnvironmentData() {
        SignerParams signerParams = new SignerParams();
        signerParams.setKeystoreFile("/Users/zhangyu/Desktop/Untitled");
        signerParams.setKeystoreKeyAlias("key0");
        signerParams.setKeystorePasswordSpec("pass:zhangyu");

        try (PasswordRetriever passwordRetriever = new PasswordRetriever()) {
            signerParams.setName("signer #0");
            try {
                //remind 解析 priKey和Cert 从参数指定的 keyStore中 或者 从keyFile和certFile中
                signerParams.loadPrivateKeyAndCerts(passwordRetriever);
            } catch (ParameterException e) {
                System.err.println(
                        "Failed to load signer \"" + signerParams.getName() + "\": "
                                + e.getMessage());
                System.exit(2);
                return;
            } catch (Exception e) {
                System.err.println("Failed to load signer \"" + signerParams.getName() + "\"");
                e.printStackTrace();
                System.exit(2);
                return;
            }

            if (signerParams.getKeystoreKeyAlias() != null) {
                v1SigBasename = signerParams.getKeystoreKeyAlias();
                Log.info("server--v1SigBasename: "+ v1SigBasename);
            } else {
                throw new RuntimeException(
                        "KeyStore key alias not available");
            }
            privateKey = signerParams.getPrivateKey();
            Log.info("server--private key: " + privateKey.toString());
            certs = signerParams.getCerts();


//            ApkSigner.SignerConfig signerConfig =
//                    new ApkSigner.SignerConfig.Builder(
//                            v1SigBasename, privateKey, certs)
//                            .build();

            publicKey = certs.get(0).getPublicKey();
            Log.info("server--certificate: " + certs.get(0).toString());
            Log.info("server--public key: " + publicKey.toString());
            int minSdkVersion = 27;
            v1SignatureDigestAlgorithm =
                    V1SchemeSigner.getSuggestedSignatureDigestAlgorithm(
                            publicKey, minSdkVersion);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return;
        }
    }
}
