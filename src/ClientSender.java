import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.RSAPublicKeySpec;
import java.time.LocalTime;
import java.util.*;
import java.util.zip.CRC32;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

// NEED TO INSTALL BouncyCastle AND JSONSimple in order for code to work.

public class ClientSender {

    private static Map<String, Object> keyPair;
    private String recipientUsername = null;
    private static DatagramSocket clientSocket;
    private PublicKey recipientKey = null;
    private String senderUsername = "Eve";

    public static void main(String[] args) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        var clientSender = new ClientSender();
        clientSender.start();
    }

    public void start() throws Exception {

        InetAddress receiverAddress = null;
        int UDP_PORT_NO = 12000;

        var scanner = new Scanner(System.in);

        String recipientList = "";
        String[] recipientIPs = new String[0];

        while (recipientList.isEmpty()) {
            System.out.println("Enter your list of IP addresses you want to send greetings to with commas separating the addresses (e.g '127.0.0.1, 127.0.0.2, 127.0.0.3' ):\n");
            recipientList = scanner.nextLine();
            recipientList = recipientList.replace(" ", "");
            recipientIPs = recipientList.split(",");
            System.out.println(Arrays.toString(recipientIPs));
        }

        var keys = ClientSender.keyPair == null ? getRSAKeys() : ClientSender.keyPair;
        ClientSender.keyPair = keys;

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


        // Custom greeting
        System.out.println("Enter a Custom Greeting: (optional)");
        String customMessage = scanner.nextLine();

        if(customMessage.isEmpty()){
            customMessage = "I hope you're doing well.";
        }



        // Attempts to send greeting to each IP address that the user entered

        for (int i = 0; i < recipientIPs.length; i++) {

            // Change IP address to list of IPs
            String UDP_IP_ADDRESS = recipientIPs[i];
            String PATTERN = "^((0|1\\d?\\d?|2[0-4]?\\d?|25[0-5]?|[3-9]\\d?)\\.){3}(0|1\\d?\\d?|2[0-4]?\\d?|25[0-5]?|[3-9]\\d?)$";

            if(!UDP_IP_ADDRESS.matches(PATTERN)) {
                System.err.println("The IP " + UDP_IP_ADDRESS + " is invalid. Please try again:");
                start();
            }

            try {
                // IP is legal is passes

                receiverAddress = InetAddress.getByName(UDP_IP_ADDRESS);

            } catch (UnknownHostException e) {
                System.err.println("The IP " + UDP_IP_ADDRESS + " is invalid, Please try again:");
                e.printStackTrace();
                start();
            }

            try {
                clientSocket = new DatagramSocket();

            } catch (SocketException ex) {
                System.err.println("Failed to initialize the client socket");
                ex.printStackTrace();
            }

            try {
                // Setting a timeout
                clientSocket.setSoTimeout(10000);
            } catch (SocketException ex) {
                System.err.println(
                        "Failed to set time out"
                );
                start();
            }

            /*
            Synchronise packet for initiating connection
             */

            System.out.println("\nInitialising Connection");

            Map<String, String> map = new HashMap<>();
            map.put("type", "sync");
            JSONObject data = new JSONObject(map);

            String checkSync = (String) data.get("type");
            long checksumSync = checksum_calculator(checkSync);


            data.put("checksum", checksumSync);

            JSONObject message = data;

            // Tries to send JSON Payload to the address
            try {
                sendData(clientSocket, message, receiverAddress, UDP_PORT_NO);
            } catch(IOException e){
                System.err.println("Attemping again...");
                e.printStackTrace();

                try{
                    sendData(clientSocket, message, receiverAddress, UDP_PORT_NO);
                } catch(IOException er){
                    System.err.println("Error, cannot establish connection with current IP, moving onto next address");
                    return;
                }
            }

            /*
            Exchanging Public Key
             */
            JSONObject key = new JSONObject(map);
            System.out.println("\nExchanging Public Key...");
            key.put("type", "sender_public_key");
            key.put("content", pemString);

            String checkKey = (String) key.get("type") + (String) key.get("content");

            long checksumKey = checksum_calculator(checkKey);


            key.put("checksum", checksumKey);

            message = key;

            try {
            // Tries to send JSON Payload to the address
            sendData(clientSocket, message, receiverAddress, UDP_PORT_NO);
            } catch(IOException e){
                System.err.println("Attemping again...");
                e.printStackTrace();

                try{
                    sendData(clientSocket, message, receiverAddress, UDP_PORT_NO);
                } catch(IOException er){
                    System.err.println("Error, cannot establish connection with current IP, moving onto next address");
                    return;
                }
            }

            /*
            Sending a request for recipient username
             */

            System.out.println("\nAsking for recipient username...");

            JSONObject request = new JSONObject();
            request.put("type", "request_username");

            String checkRequest = (String) request.get("type");
            long checksumRequest = checksum_calculator(checkRequest);

            request.put("checksum", checksumRequest);

            message = request;

            try {
            // Tries to send JSON Payload to the address
            sendData(clientSocket, message, receiverAddress, UDP_PORT_NO);
            } catch(IOException e){
                System.err.println("Attemping again...");
                e.printStackTrace();

                try{
                    sendData(clientSocket, message, receiverAddress, UDP_PORT_NO);
                } catch(IOException er){
                    System.err.println("Error, cannot establish connection with current IP, moving onto next address");
                    return;
                }
            }

            /*
            Sending greeting message
             */

            String timeOfDay = "";
            LocalTime eleven = LocalTime.of(11, 00);
            LocalTime four = LocalTime.of(04, 00);
            LocalTime six = LocalTime.of(18, 00);
            if (LocalTime.now().isAfter(four) && LocalTime.now().isBefore(eleven)) {
                timeOfDay = "Good Morning ";
            } else if (LocalTime.now().isAfter(eleven) && LocalTime.now().isBefore(six)) {
                timeOfDay = "Good Afternoon ";
            } else {
                timeOfDay = "Good Evening ";
            }

            String fullGreeting = "\n" + timeOfDay + recipientUsername + "\n" + customMessage + "\nFrom " + this.senderUsername;

            byte[] encryptedMessage = encryptMessage(fullGreeting, this.recipientKey);

            var encodedMessage = new String(Base64.getEncoder().encode(encryptedMessage), StandardCharsets.ISO_8859_1);

            JSONObject greeting = new JSONObject();
            greeting.put("type", "message");
            greeting.put("content", encodedMessage);

            String checkMessage = (String) greeting.get("type") + (String) greeting.get("content");
            long checksumMessage = checksum_calculator(checkMessage);

            greeting.put("checksum", checksumMessage);
            message = greeting;

            System.out.println("\nSending message:" + fullGreeting);

            // Tries to send JSON Payload to the address
            try {
                sendData(clientSocket, message, receiverAddress, UDP_PORT_NO);
            } catch (IOException e){
                System.err.println("Attemping again...");
                e.printStackTrace();

                try{
                    sendData(clientSocket, message, receiverAddress, UDP_PORT_NO);
                } catch(IOException er){
                    System.err.println("Error, cannot establish connection with current IP, moving onto next address");
                    return;
                }
            }


            /*
            Ending connection with current recipient
             */

            JSONObject finish = new JSONObject();
            finish.put("type", "fin");

            String checkFin = (String) finish.get("type");
            long checksumFin = checksum_calculator(checkFin);

            finish.put("checksum", checksumFin);
            message = finish;

            System.out.println("\nRequest to close connection...");
            // Tries to send JSON Payload to the address
            try{
                sendData(clientSocket, message, receiverAddress, UDP_PORT_NO);
            } catch (IOException e){
                System.err.println("Attemping again...");
                e.printStackTrace();

                try{
                    sendData(clientSocket, message, receiverAddress, UDP_PORT_NO);
                } catch(IOException er){
                    System.err.println("Error, cannot establish connection with current IP, moving onto next address");
                    return;
                }
            }

        }


    }

    public void sendData(DatagramSocket socket, JSONObject message, InetAddress receiverAddress, Integer port) throws IOException, BadPaddingException, IllegalBlockSizeException {

        String toSend = message.toJSONString();
        var messageBuffer = toSend.getBytes(StandardCharsets.ISO_8859_1);

      //  try {
            // Setting the Receiver address and establishing a socket connection
            // Attempts to send data to recipient
            clientSocket.send(new DatagramPacket(
                    messageBuffer,
                    messageBuffer.length,
                    receiverAddress,
                    port
            ));


            System.out.println("Awaiting Ack");
            receiveAck(receiverAddress, port);

            if(message.get("type") == "sync"){
                return;
            }

            if(message.get("type") == "fin"){
                System.out.println("\nConnection Terminated");
                clientSocket.close();
                return;
            }


            byte[] buffer = new byte[1024];

            var incomingPacket = new DatagramPacket(
                    buffer,
                    buffer.length,
                    receiverAddress,
                    port
            );

            // Attempts to receive data from recipient
            clientSocket.receive(incomingPacket);

            var messageResponse = new String(
                    incomingPacket.getData(), 0, incomingPacket.getLength(),
                    StandardCharsets.ISO_8859_1
            );

            String incomingType = null;


            try {

                JSONParser jsonParser = new JSONParser();
                Object object = jsonParser.parse(messageResponse);
                JSONObject jsonObject = (JSONObject) object;
                incomingType = (String) jsonObject.get("type");
                System.out.println("\nJSON Type of incoming data ---  " + incomingType);

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

                if (incomingType.equals("message")) {

                    byte[] decodedResponse = Base64.getDecoder().decode(incomingResponse.getBytes(StandardCharsets.ISO_8859_1));

                    PrivateKey privateKey = (PrivateKey) ClientSender.keyPair.get("private");

                    String decryptedResponse = decryptMessage(decodedResponse, privateKey);
                    System.out.println("Received Message: \n" + decryptedResponse);

                }

                if(incomingType.equals("recipient_public_key")){

                    String pubKey = jsonObject.get("content").toString();

                    String publicKeyPEM = pubKey
                            .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                            .replaceAll(System.lineSeparator(), "")
                            .replace("-----END RSA PUBLIC KEY-----", "");


                    //byte[] decoded = Base64.getDecoder().decode(publicKeyPEM.getBytes());

                    byte [] decoded = Base64.getMimeDecoder().decode(publicKeyPEM.getBytes(StandardCharsets.ISO_8859_1));

                    org.bouncycastle.asn1.pkcs.RSAPublicKey pkcs1PublicKey = org.bouncycastle.asn1.pkcs.RSAPublicKey.getInstance(decoded);
                    BigInteger modulus = pkcs1PublicKey.getModulus();
                    BigInteger publicExponent = pkcs1PublicKey.getPublicExponent();
                    RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, publicExponent);
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    this.recipientKey = keyFactory.generatePublic(keySpec);
                    System.out.println("Received Recipient Key");

                }

                if (incomingType.equals("recipient_username")) {

                    String encryptedUsername = (String) jsonObject.get("content");

                    byte[] decodedUsername = Base64.getDecoder().decode(encryptedUsername.getBytes(StandardCharsets.ISO_8859_1));

                    PrivateKey privateKey = (PrivateKey) ClientSender.keyPair.get("private");

                    String decryptedUsername = decryptMessage(decodedUsername, privateKey);
                    System.out.println("Recipient Username: \n" + decryptedUsername);
                    this.recipientUsername = decryptedUsername;
                }

                sendAck(receiverAddress, port);

            } catch (Exception ex) {
                ex.printStackTrace();
                return;
            }

            if (incomingType.equals("sync")) {
                System.out.println("\nEstablished a connection with recipient " + receiverAddress);
                return;
            }

/*
        } catch (IOException ex) {
            // If we encounter an IOException, it means there was a
            // problem communicating (IO = Input/Output) so we'll log
            // the error.

 */
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
            clientSocket.send(new DatagramPacket(
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
        byte[] buffer = new byte[256];

        var incomingPacket = new DatagramPacket(
                buffer,
                buffer.length,
                receiverAddress,
                port
        );

        // Attempts to receive data from recipient
        clientSocket.receive(incomingPacket);

        var messageResponse = new String(
                incomingPacket.getData(), 0, incomingPacket.getLength(),
                StandardCharsets.ISO_8859_1
        );

        try {

            JSONParser jsonParser = new JSONParser();
            Object object = jsonParser.parse(messageResponse);
            JSONObject jsonObject = (JSONObject) object;
            String incomingType = (String) jsonObject.get("type");
            System.out.println("JSON Type of incoming data ---  " + incomingType);

            if(!incomingType.equals("ack")){
                throw new SocketException();
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

    private static String decryptMessage(byte[] encryptedResponse, PrivateKey privateKey) throws Exception {

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(cipher.doFinal(encryptedResponse), StandardCharsets.ISO_8859_1);
    }

    private static byte[] encryptMessage(String outgoingMessage, PublicKey recipientKey) throws Exception {

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, recipientKey);

        byte[] encodedGreeting = outgoingMessage.getBytes();

        byte[] encryptedGreeting = cipher.doFinal(encodedGreeting);


        return encryptedGreeting;
    }

    private static long checksum_calculator(String json){
        var crc32 = new CRC32();

        crc32.update(json.getBytes());

        return crc32.getValue();
    }

}