import myapksig.Log;
import myapksig.MyEnvironment;
import myapksig.internal.apk.v1.V1SchemeSigner;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;

public class Server {

    public static void main(String[] args) throws IOException {

        MyEnvironment.loadEnvironmentData();
        Log.info("Environment initiating finished");
        ServerSocket serverSocket = new ServerSocket(8848);
        try {
            InputStream inputStream;
            OutputStream outputStream;
            byte[] commandReceived = new byte[2048];
            Socket socket = serverSocket.accept();
            inputStream = socket.getInputStream();
            outputStream = socket.getOutputStream();

            while (true) {
                int len = inputStream.read(commandReceived);
                if (len == -1) {
                    inputStream.close();
                    outputStream.close();
                    return;
                }

                Log.info("server--len of bytes received from client: " + len);
                String command = new String(commandReceived, 0, len);
                Log.info("server--Get command from client: " + command);
                switch (command) {
                    case "SIGNNAME":
                        sendSignName(inputStream, outputStream);
                        break;
                    case "X509CERTS":
                        sendCerts(inputStream, outputStream);
                        break;
                    case "V1SIGN":
                        sendRSAFile(inputStream, outputStream);
                        break;
                    case "V2SIGN":
                        sendV2SignBytes(inputStream, outputStream);
                        break;
                }
            }

        } catch (Exception e) {
            Log.error("Socket accept failed. Exception:{}", e.getMessage());
        } finally {
            if (serverSocket != null) {
                serverSocket.close();
            }
        }
    }

    private static void sendV2SignBytes(
            InputStream inputStream,
            OutputStream outputStream)
            throws IOException, InvalidKeyException, SignatureException, NoSuchAlgorithmException {
        Log.info("okmijn");
        byte[] input = new byte[1084576];
        int len = inputStream.read(input);
        System.out.println("v2 file length: "+len);
        byte[] data = Arrays.copyOf(input, len);
        byte[] signatureBytes;
        String jcaSignatureAlgorithm = "SHA256withRSA";
        try {
            Signature signature = Signature.getInstance(jcaSignatureAlgorithm);
            signature.initSign(MyEnvironment.privateKey);
            signature.update(data);
            signatureBytes = signature.sign();

            outputStream.write(signatureBytes);
            outputStream.flush();
        } catch (InvalidKeyException e) {
            throw new InvalidKeyException("Failed to sign using " + jcaSignatureAlgorithm, e);
        } catch (SignatureException e) {
            throw new SignatureException("Failed to sign using " + jcaSignatureAlgorithm, e);
        }
    }

    private static void sendRSAFile(InputStream inputStream, OutputStream outputStream)
            throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Log.info("qazwsxedc");
        byte[] signatureFileBytes = new byte[1084576]; //1M
        int length = inputStream.read(signatureFileBytes);
        System.out.println("v1 file length: "+length);

        byte[] sfFile = Arrays.copyOf(signatureFileBytes, length);
        byte[] RSAFile = V1SchemeSigner.generateSignatureBlock2(sfFile);

        outputStream.write(RSAFile);
        outputStream.flush();
    }

    private static void sendCerts(InputStream inputStream, OutputStream outputStream) throws IOException {
        Log.info("server--sendCerts Methods");
        ObjectOutputStream oout = new ObjectOutputStream(outputStream);
        oout.writeObject(MyEnvironment.certs);
        oout.flush();
    }

    private static void sendSignName(InputStream inputStream, OutputStream outputStream) throws IOException {
        Log.info("Server--sendSignName to Client");
        outputStream.write(MyEnvironment.v1SigBasename.getBytes());
        outputStream.flush();
    }
}

