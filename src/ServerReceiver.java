import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import javax.crypto.Cipher;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.CRC32;

// NEED TO INSTALL BouncyCastle AND JSONSimple in order for code to work.

public class ServerReceiver {


    private static DatagramSocket receiverSocket;
    private static Integer UDP_PORT_NO = 12000;
    private PublicKey senderKey = null;

    private static Map<String,Object> keyPair;

    public static void main(String[] args) throws IOException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        var serverReceiver = new ServerReceiver();
        serverReceiver.receiveData();


    }

    public void receiveData() throws SocketException {
        if (receiverSocket != null) return;

        try {
            receiverSocket = new DatagramSocket(UDP_PORT_NO);

            System.out.println("Listening on port " + UDP_PORT_NO);

            byte[] buffer = new byte[256];

            var incomingPacket = new DatagramPacket(buffer, buffer.length);
            receiverSocket.receive(incomingPacket);

            var clientSenderAddress = incomingPacket.getAddress();
            var clientPort = incomingPacket.getPort();

            var message = new String(
                    incomingPacket.getData(),
                    0,
                    incomingPacket.getLength(),
                    StandardCharsets.ISO_8859_1
            );

            String incomingType = null;

            try {

                JSONParser jsonParser = new JSONParser();
                Object object = jsonParser.parse(message);
                JSONObject jsonObject = (JSONObject) object;
                incomingType = (String) jsonObject.get("type");

                System.out.println("\nType of incoming data :" +  incomingType);

                String incomingResponse = jsonObject.containsKey("content") ? (String) jsonObject.get("content") : "";

                if(jsonObject.containsKey("checksum")) {
                    long incomingChecksum = (long) jsonObject.get("checksum");

                    String checksum_sequence = incomingType + incomingResponse;
                    var crc32 = new CRC32();
                    crc32.update(checksum_sequence.getBytes());
                    long checksumCal = crc32.getValue();

                    if (incomingChecksum != checksumCal) {
                        System.out.println("Checksums do not match");
                        throw new Exception("Checksums do not match");
                    } else {
                        System.out.println("Checksums match");
                    }
                }

            } catch (Exception ex) {
                ex.printStackTrace();
            }

            if (incomingType != null) {

                sendAck(clientSenderAddress, clientPort);

                sendResponse(incomingType, clientSenderAddress, clientPort);
            }


        } catch (IOException e) {
            System.err.println("Communication Error");
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void keepListening() throws Exception {
        byte[] buffer = new byte[2048];
        var incomingPacket = new DatagramPacket(buffer, buffer.length);
        receiverSocket.receive(incomingPacket);

        var clientSenderAddress = incomingPacket.getAddress();
        var clientPort = incomingPacket.getPort();

        var message = new String(
                incomingPacket.getData(),
                0,
                incomingPacket.getLength(),
                StandardCharsets.ISO_8859_1
        );
        //System.out.println("Incoming package data is " + incomingPacket.getData());

        String incomingType = null;


        try {

            JSONParser jsonParser = new JSONParser();
            Object object = jsonParser.parse(message);
            JSONObject jsonObject = (JSONObject) object;
            incomingType = (String) jsonObject.get("type");

            //System.out.println("JSON Object " + jsonObject);
            System.out.println("\nType of incoming data :" +  incomingType);


            if(incomingType.equals("message")){
                String incomingMessage = (String) jsonObject.get("content");

                byte[] decodedMessage = Base64.getDecoder().decode(incomingMessage.getBytes(StandardCharsets.ISO_8859_1));

                PrivateKey privateKey = (PrivateKey) ServerReceiver.keyPair.get("private");
                String decryptedMessage = decryptMessage(decodedMessage, privateKey);
                System.out.println(decryptedMessage);

            }
            if(incomingType.equals("sender_public_key")){
                String senderKey = jsonObject.get("content").toString();


                String senderKeyPEM = senderKey
                        .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                        .replaceAll(System.lineSeparator(), "")
                        .replace("-----END RSA PUBLIC KEY-----", "");



                byte [] decoded = Base64.getMimeDecoder().decode(senderKeyPEM.getBytes(StandardCharsets.ISO_8859_1));
                //Base64.getDecoder().decode(senderKeyPEM.getBytes(StandardCharsets.ISO_8859_1));


                org.bouncycastle.asn1.pkcs.RSAPublicKey pkcs1PublicKey = org.bouncycastle.asn1.pkcs.RSAPublicKey.getInstance(decoded);
                BigInteger modulus = pkcs1PublicKey.getModulus();
                BigInteger publicExponent = pkcs1PublicKey.getPublicExponent();
                RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, publicExponent);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                this.senderKey = keyFactory.generatePublic(keySpec);
                System.out.println("Saved Sender Public Key");



            }

            System.out.println("Sending Ack...");
            sendAck(clientSenderAddress, clientPort);

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        sendResponse(incomingType, clientSenderAddress, clientPort);

    }

    public void sendResponse(String incomingType, InetAddress address, Integer port) throws Exception {

        String response = "";

        if (incomingType.equals("sync")){
            keepListening();
            return;
        }


        if(incomingType.equals("sender_public_key")){
            System.out.println("\nExchanging Receiver Public Key...");

            JSONObject key = new JSONObject();
            key.put("type", "recipient_public_key");
            key.put("content", getPem());

            long checksumKey = checksum_calculator((String) key.get("type") + (String) key.get("content"));

            key.put("checksum", checksumKey);

            response = key.toJSONString();


        } else if (incomingType.equals("request_username")) {
            System.out.println("\nRequest for Username...");

            String localUsername = "Eve";
            byte[] encryptedUsername = encryptMessage(localUsername, this.senderKey);
            var encodedUsername = new String(Base64.getEncoder().encode(encryptedUsername), StandardCharsets.ISO_8859_1);

            JSONObject usernameData = new JSONObject();
            usernameData.put("type", "recipient_username");
            usernameData.put("content", encodedUsername);

            System.out.println("\nSending username...");

            long checksumUser = checksum_calculator((String) usernameData.get("type") + (String) usernameData.get("content"));

            usernameData.put("checksum", checksumUser);

            response = usernameData.toJSONString();


        } else if (incomingType.equals("message")) {
            System.out.println("\nGreeting Received, Sending Reply");

            String greetingResponse = "Thank you for your greeting";
            byte[] encryptedMessage = encryptMessage(greetingResponse, this.senderKey);
            var encodedResponse = new String(Base64.getEncoder().encode(encryptedMessage), StandardCharsets.ISO_8859_1);

            JSONObject greetingData = new JSONObject();
            greetingData.put("type", "message");
            greetingData.put("content", encodedResponse);

            long checksumGreet = checksum_calculator((String) greetingData.get("type") + (String) greetingData.get("content"));

            greetingData.put("checksum", checksumGreet);

            response = greetingData.toJSONString();

        } else if (incomingType.equals("fin")) {
            System.out.println("\nRequest to close connection");

            JSONObject fin = new JSONObject();
            fin.put("type", "fin");

            long checksumFin = checksum_calculator((String) fin.get("type"));

            fin.put("checksum", checksumFin);

            response = fin.toJSONString();

        }

        var responseBuffer = response.getBytes(StandardCharsets.ISO_8859_1);
        try {
            receiverSocket.send(new DatagramPacket(
                    responseBuffer,
                    responseBuffer.length,
                    address,
                    port
            ));

        } catch (IOException ex) {
            System.out.println("Could not send response");
            ex.printStackTrace();
        }

        if(incomingType.equals("fin")){
            System.out.println("Closing Connection...");
            receiverSocket.close();
            return;
        }

        System.out.println("\nAwaiting Ack");
        receiveAck(address, port);



        keepListening();
    }

    public static void sendAck(InetAddress address, Integer port){

        JSONObject data = new JSONObject();
        data.put("type", "ack");
        String checkKey = (String) data.get("type");
        long checksumKey = checksum_calculator(checkKey);
        data.put("checksum", checksumKey);
        String ack = data.toJSONString();

        var responseBuffer = ack.getBytes(StandardCharsets.ISO_8859_1);
        try {
            receiverSocket.send(new DatagramPacket(
                    responseBuffer,
                    responseBuffer.length,
                    address,
                    port
            ));
        } catch (IOException ex) {
            System.out.println("Could not send ACK");
            ex.printStackTrace();
        }
        System.out.println("\nSent Ack");
    }

    public static void receiveAck(InetAddress receiverAddress, Integer port) throws IOException {
        byte[] buffer = new byte[1024];

        var incomingPacket = new DatagramPacket(
                buffer,
                buffer.length,
                receiverAddress,
                port
        );

        // Attempts to receive data from recipient
        receiverSocket.receive(incomingPacket);

        var messageResponse = new String(
                incomingPacket.getData(), 0, incomingPacket.getLength(),
                StandardCharsets.ISO_8859_1
        );

        try {

            JSONParser jsonParser = new JSONParser();

            Object object = jsonParser.parse(messageResponse);

            JSONObject jsonObject = (JSONObject) object;
            String incomingType = (String) jsonObject.get("type");
            System.out.println("\nJSON Type of incoming data ---  " + incomingType);

            if(!incomingType.equals("ack")){
                throw new Exception("Ack not Received");
            }

        } catch(Exception ex) {
            ex.printStackTrace();
        }

    }

    private static Map<String,Object> getRSAKeys(){

        // Generating RSA keys
        KeyPairGenerator generator = null;
        try {
            generator = KeyPairGenerator.getInstance("RSA");

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();

        // Extract Private and Public Key
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        Map<String, Object> keys = new HashMap<String,Object>();
        keys.put("private", privateKey);
        keys.put("public", publicKey);
        return keys;

    }

    private static String decryptMessage(byte[] encryptedMessage, PrivateKey privateKey) throws Exception {

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(cipher.doFinal(encryptedMessage), StandardCharsets.ISO_8859_1);


    }

    private static byte[] encryptMessage(String outgoingMessage, PublicKey senderKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, senderKey);

        byte[] encodedGreeting = outgoingMessage.getBytes();

        byte[] encryptedGreeting = cipher.doFinal(encodedGreeting);


        return encryptedGreeting;

    }

    private static String getPem() throws IOException {
        var keys = ServerReceiver.keyPair == null ? getRSAKeys() : ServerReceiver.keyPair;
        ServerReceiver.keyPair = keys;
        PublicKey publicKey = (PublicKey) keys.get("public");

        byte[] pubBytes = publicKey.getEncoded();

        SubjectPublicKeyInfo spkInfo = SubjectPublicKeyInfo.getInstance(pubBytes);
        ASN1Primitive primitive = spkInfo.parsePublicKey();
        byte[] publicKeyPKCS1 = primitive.getEncoded();

        PemObject pemObject = new PemObject("RSA PUBLIC KEY", publicKeyPKCS1);
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        String pemString = stringWriter.toString();


        return pemString;

    }

    private static long checksum_calculator(String json){
        var crc32 = new CRC32();

        crc32.update(json.getBytes());

        return crc32.getValue();
    }

}