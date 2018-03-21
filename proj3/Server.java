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
import java.util.Scanner;

class Server {
    public static HashMap<String, ClientConnection> userSockets;
    public static final String password = "password";

    public static void main(String args[]) {
        int portNum = Integer.parseInt(args[0]);

        userSockets = new HashMap<>();

		Runtime.getRuntime().addShutdownHook(new Thread() {
            @Override
            public void run() {
				System.out.println("running shutdown hook");
				Iterator it = Server.userSockets.entrySet().iterator();
				while (it.hasNext()) {
					Map.Entry pair = (Map.Entry) it.next();
					ClientConnection cc = (ClientConnection)pair.getValue();
					try {
						cc.sc.write(ByteBuffer.wrap("!shutdown".getBytes()));
						cc.sc.close();
					} catch (IOException e) {
						System.out.println(e.getMessage());
					}
				}
            }
        });

        SocketChannel sc;
        try {
            ServerSocketChannel c = ServerSocketChannel.open();
            c.bind(new InetSocketAddress(portNum));
            Encryption crypto = new Encryption();
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
}

class TcpServerThread extends Thread {
    SocketChannel sc;
    SecretKey key;
    Console cons;
    String username;

    TcpServerThread(SocketChannel sc, SecretKey key) {
        this.sc = sc;
        this.key = key;
        cons = System.console();
        username = "";
    }

    public void run() {
        String command;

        Encryption crypto = new Encryption();
        SecureRandom r = new SecureRandom();
        try {
            while (true) {
                ByteBuffer ivbuffer = ByteBuffer.allocate(16);
                sc.read(ivbuffer);
                IvParameterSpec iv = new IvParameterSpec(ivbuffer.array());

                ByteBuffer buffer = ByteBuffer.allocate(4096);
                int size = sc.read(buffer);
                buffer.flip();
                byte[] bytes = new byte[size];
                buffer.get(bytes,0,size);

                byte[] decryptedMessage = crypto.decrypt(bytes, key, iv);
//                byte[] a = new byte[buffer.remaining()];
//                buffer.get(a);
                command = new String(decryptedMessage);
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

                    sc.write(ByteBuffer.wrap(response.getBytes()));
                } else if (args[0].equals("!kick")) {
                    if (args[1].equals(Server.password)) {
                        Iterator it = Server.userSockets.entrySet().iterator();
                        while (it.hasNext()) {
                            Map.Entry pair = (Map.Entry) it.next();
                            if (pair.getKey().equals(args[2])) {
                                SocketChannel sc = (SocketChannel) pair.getValue();
                                sc.write(ByteBuffer.wrap("You have been kicked.".getBytes()));
                                sc.close();
                                it.remove();
                            }
                        }
                    } else {
                        sc.write(ByteBuffer.wrap("Naughty naughty! Bad proj3.Client!".getBytes()));
                    }
                } else if (args[0].equals("!all")) {
                    Iterator it = Server.userSockets.entrySet().iterator();
                    while (it.hasNext()) {
                        Map.Entry pair = (Map.Entry)it.next();
                        if (!pair.getValue().equals(sc)) {
                            SocketChannel sc = (SocketChannel)pair.getValue();
                            String response = command.substring(command.indexOf(' ') + 1);
                            sc.write(ByteBuffer.wrap((username + ": " + response).getBytes()));
                        }
                    }
                } else {
					try {
//                        byte ivbytes[] = new byte[16];
//                        r.nextBytes(ivbytes);
//                        IvParameterSpec sendiv = new IvParameterSpec(ivbytes);
                        byte[] message = (username + ": " + command.substring(command.indexOf(' ') + 1)).getBytes();
                        byte[] encryptedMessage = crypto.encrypt(message, Server.userSockets.get(args[0]).symmetricKey, iv);
                        Server.userSockets.get(args[0]).sc.write(ByteBuffer.wrap(iv.getIV()));
                        Server.userSockets.get(args[0]).sc.write(ByteBuffer.wrap(encryptedMessage));
//                        sc.write(buf);

//                    	Server.userSockets.get(args[0]).sc.write(ByteBuffer.wrap());
					} catch (NullPointerException e) {
						sc.write(ByteBuffer.wrap("Requested user does not exist.".getBytes()));
					}
                }
            }
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
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
