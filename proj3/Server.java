package proj3;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

class Server {
    public static HashMap<String, ClientConnection> userSockets;
    public static final String password = "password";

    public static void main(String args[]) {
        int portNum = Integer.parseInt(args[0]);

        userSockets = new HashMap<>();
        Encryption crypto = new Encryption();

		Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("running shutdown hook");
            Iterator it = Server.userSockets.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry pair = (Map.Entry) it.next();
                ClientConnection cc = (ClientConnection)pair.getValue();
                try {
                    Server.writeSocket("!shutdown", cc, new SecureRandom(), crypto);
                    cc.sc.close();
                } catch (IOException e) {
                    System.out.println(e.getMessage());
                }
            }
        }));

        SocketChannel sc;
        try {
            ServerSocketChannel c = ServerSocketChannel.open();
            c.bind(new InetSocketAddress(portNum));
            crypto.setPrivateKey("RSApriv.der");
            while (true) {
                sc = c.accept();
                ByteBuffer encryptedSymKey = ByteBuffer.allocate(256);
                sc.read(encryptedSymKey);
                byte decryptedsecret[] = crypto.RSADecrypt(encryptedSymKey.array());
		        SecretKey symmetricKey = new SecretKeySpec(decryptedsecret, "AES");

                userSockets.put("", new ClientConnection(sc, symmetricKey));
                TcpServerThread t = new TcpServerThread(sc, symmetricKey);
                t.start();
            }
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }

    private static void writeSocket(String msg, ClientConnection client, SecureRandom r, Encryption crypto) throws IOException {
        byte ivbytes[] = new byte[16];
        r.nextBytes(ivbytes);
        IvParameterSpec iv = new IvParameterSpec(ivbytes);

        byte[] encryptedMessage = crypto.encrypt(msg.getBytes(), client.symmetricKey, iv);
        ByteBuffer[] bufs = {ByteBuffer.wrap(iv.getIV()), ByteBuffer.wrap(encryptedMessage)};
        client.sc.write(bufs);
    }
}

class TcpServerThread extends Thread {
    private SocketChannel sc;
    private SecretKey key;
    private Console cons;
    private String username;
    private Encryption crypto;
    private SecureRandom r;

    TcpServerThread(SocketChannel sc, SecretKey key) {
        this.sc = sc;
        this.key = key;
        cons = System.console();
        username = "";
        crypto = new Encryption();
        r = new SecureRandom();
    }

    public void run() {
        String command;

        try {
            while (true) {
//                ByteBuffer ivbuffer = ByteBuffer.allocate(16);
//                sc.read(ivbuffer);
//                IvParameterSpec iv = new IvParameterSpec(ivbuffer.array());
//
//                ByteBuffer buffer = ByteBuffer.allocate(4096);
//                int size = sc.read(buffer);
//                buffer.flip();
//                byte[] bytes = new byte[size];
//                buffer.get(bytes,0,size);
//                System.out.println(bytes.length);
//                byte[] decryptedMessage = crypto.decrypt(bytes, key, iv);
//                byte[] a = new byte[buffer.remaining()];
//                buffer.get(a);
                command = new String(readSocket());
				if (command.equals("")) {
					continue;
				}

                System.out.println("Got from client " + username + ": " + command);
                final String[] args;
                args = command.split(" ");

                if (args[0].equals("!rename")) {
                    username = args[1];

                    HashMap<String, ClientConnection> userSocketsCopy = new HashMap<>(Server.userSockets);
                    userSocketsCopy.forEach( (name, cc) -> {
                        if (this.sc.equals(cc.sc)) {
                            Server.userSockets.remove(name);
                            Server.userSockets.put(args[1], new ClientConnection(sc, cc.symmetricKey));
                            System.out.println(Server.userSockets);
                        }
                    });
                } else if (args[0].equals("!list")) {
                    String response = "";
                    Iterator it = Server.userSockets.entrySet().iterator();

                    while (it.hasNext()) {
                        Map.Entry pair = (Map.Entry)it.next();
                        response = response.concat(pair.getKey() + "\n");
                    }

                    writeSocket(response, Server.userSockets.get(username));
                } else if (args[0].equals("!kick")) {
                    if (args[1].equals(Server.password)) {
                        Iterator it = Server.userSockets.entrySet().iterator();
                        while (it.hasNext()) {
                            Map.Entry pair = (Map.Entry) it.next();
                            if (pair.getKey().equals(args[2])) {
                                ClientConnection cc = (ClientConnection) pair.getValue();
                                writeSocket("You have been kicked.", cc);
                                cc.sc.close();
                                it.remove();
                            }
                        }
                    } else {
                        writeSocket("Naughty naughty! Bad Client!", Server.userSockets.get(username));
                    }
                } else if (args[0].equals("!all")) {
                    Iterator it = Server.userSockets.entrySet().iterator();
                    while (it.hasNext()) {
                        Map.Entry pair = (Map.Entry)it.next();
                        ClientConnection cc = (ClientConnection)pair.getValue();
                        if (!cc.sc.equals(sc)) {
                            String response = command.substring(command.indexOf(' ') + 1);
                            response = username + ": " + response;
                            writeSocket(response, cc);
                        }
                    }
                } else {
					try {
//                        byte ivbytes[] = new byte[16];
//                        r.nextBytes(ivbytes);
//                        IvParameterSpec sendiv = new IvParameterSpec(ivbytes);
                        String message = (username + ": " + command.substring(command.indexOf(' ') + 1));
                        writeSocket(message, Server.userSockets.get(args[0]));

//                        byte[] encryptedMessage = crypto.encrypt(message, Server.userSockets.get(args[0]).symmetricKey, iv);
//                        Server.userSockets.get(args[0]).sc.write(ByteBuffer.wrap(iv.getIV()));
//                        Server.userSockets.get(args[0]).sc.write(ByteBuffer.wrap(encryptedMessage));
//                        sc.write(buf);

//                    	Server.userSockets.get(args[0]).sc.write(ByteBuffer.wrap());
					} catch (NullPointerException e) {
						writeSocket("Requested user does not exist.", Server.userSockets.get(username));
					}
                }
            }
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }

    private byte[] readSocket() throws IOException {
//        ByteBuffer ivbuffer = ByteBuffer.allocate(16);
//        ByteBuffer buffer = ByteBuffer.allocate(4096);
        ByteBuffer[] bufs = {ByteBuffer.allocate(16), ByteBuffer.allocate(4096)};
        sc.read(bufs);
        bufs[0].flip();
        IvParameterSpec iv = new IvParameterSpec(bufs[0].array());

        int size = 4096 - bufs[1].remaining();
        bufs[1].flip();
        byte[] bytes = new byte[size];
        bufs[1].get(bytes,0,size);
//        System.out.println(bytes.length);
        return crypto.decrypt(bytes, key, iv);
    }

    private void writeSocket(String msg, ClientConnection client) throws IOException {
        byte ivbytes[] = new byte[16];
        r.nextBytes(ivbytes);
        IvParameterSpec iv = new IvParameterSpec(ivbytes);

        byte[] encryptedMessage = crypto.encrypt(msg.getBytes(), client.symmetricKey, iv);
        ByteBuffer[] bufs = {ByteBuffer.wrap(iv.getIV()), ByteBuffer.wrap(encryptedMessage)};
        client.sc.write(bufs);
    }
}

class ClientConnection {
    public SocketChannel sc;
    public SecretKey symmetricKey;

    public ClientConnection(SocketChannel sc, SecretKey symmetricKey) {
        this.sc = sc;
        this.symmetricKey = symmetricKey;
    }

    public String toString() {
        return "SocketChannel: " + sc + "  SecretKey: " + symmetricKey.getEncoded();
    }
}
