package myapksig;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.cert.X509Certificate;
import java.util.List;

public class ServerConnection {
    private static ServerConnection connection;

    private Socket socket;

    private ServerConnection() {

    }

    public static void initConnection()throws IOException{
        if (connection == null) {
            connection = new ServerConnection();
            connection.socket = new Socket("localhost", 8848);
        }
    }

    /**
     * (multi threads unsafe)
     */
    public static ServerConnection getConnection() throws IOException {
        return connection;
    }

    public String getV1SignBasename() throws IOException {
        String v1SignBasename = null;
        //根据输入输出流和服务端连接
        OutputStream outputStream = socket.getOutputStream();//获取一个输出流，向服务端发送信息
        outputStream.write("SIGNNAME".getBytes());
        outputStream.flush();

        socket.shutdownOutput();//关闭输出流

        InputStream inputStream = socket.getInputStream();//获取一个输入流，接收服务端的信息
        int maxLen = 2048;
        byte[] contextBytes = new byte[maxLen];
        int realLen;
        StringBuffer message = new StringBuffer();
        while ((realLen = inputStream.read(contextBytes, 0, maxLen)) != -1) {
            message.append(new String(contextBytes, 0, realLen));
        }

        System.out.println("reply from server: " + message);
        v1SignBasename = message.toString();
        //关闭相对应的资源
        inputStream.close();
        outputStream.close();

        return v1SignBasename;
    }

    public List<X509Certificate> getCerts() throws IOException, ClassNotFoundException {
        List<X509Certificate> x509Certs = null;
        OutputStream outputStream = socket.getOutputStream();
        outputStream.write("X509CERTS".getBytes());
        outputStream.flush();
        socket.shutdownOutput();//关闭输出流

        InputStream inputStream = socket.getInputStream();
        ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
        x509Certs = (List<X509Certificate>) objectInputStream.readObject();
        outputStream.close();
        inputStream.close();
        objectInputStream.close();
        return x509Certs;
    }

    public void closeSocket() throws IOException {
        socket.close();
    }

    /**
     * 上传.SF文件buye[]到服务器，从服务器获取.RSA文件byte[]
     * @param signatureFileBytes .SF文件buye[]
     * @return byte[] .RSA文件
     * @throws IOException
     */
    public byte[] getSignatureBlock(byte[] signatureFileBytes) throws IOException {
        byte[] v1SignatureBlock = null;

        OutputStream outputStream = socket.getOutputStream();
        outputStream.write("V1SIGN".getBytes());
        outputStream.flush();
        outputStream.write(signatureFileBytes);
        outputStream.flush();
        socket.shutdownOutput();//关闭输出流

        InputStream inputStream = socket.getInputStream();
        inputStream.read(v1SignatureBlock);
        outputStream.close();
        inputStream.close();
        return v1SignatureBlock;
    }

    public byte[] getV2SignatureBytes(byte[] data) throws IOException {
        byte[] v2SignatureBytes = null;

        OutputStream outputStream = socket.getOutputStream();
        outputStream.write("V2SIGN".getBytes());
        outputStream.write(data);
        outputStream.flush();
        socket.shutdownOutput();//关闭输出流

        InputStream inputStream = socket.getInputStream();
        inputStream.read(v2SignatureBytes);
        outputStream.close();
        inputStream.close();
        return v2SignatureBytes;
    }
}
