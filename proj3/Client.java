package proj3;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;
import java.security.SecureRandom;

class Client {
    public static void main(String args[]) {
        Console cons = System.console();
        int portNum = Integer.parseInt(args[0]);
        String ipAddr = args[1];

        String message = "";
		boolean printPrompt = false;

        SecretKey symmetricKey;
        SecureRandom r = new SecureRandom();
        try {
            SocketChannel sc = SocketChannel.open();
            sc.connect(new InetSocketAddress(ipAddr, portNum));

            Encryption crypto = new Encryption();
            crypto.setPublicKey("RSApub.der");
            symmetricKey = crypto.generateAESKey();
            byte encryptedsecret[] = crypto.RSAEncrypt(symmetricKey.getEncoded());
            sc.write(ByteBuffer.wrap(encryptedsecret));

            ClientThread t = new ClientThread(sc, symmetricKey);
            t.start();

            String username = cons.readLine("What username? ");
            username = "!rename " + username;
            Client.writeSocket(username, sc, r, crypto, symmetricKey);
//            sc.write(ByteBuffer.wrap(username.getBytes()));

			System.out.print(">> ");
            while (true) {
				if (printPrompt) {
					System.out.print(">> ");
				}
				message = cons.readLine();
                if (message.equals("!quit")) {
                    break;
                }
                Client.writeSocket(message, sc, r, crypto, symmetricKey);
//                byte ivbytes[] = new byte[16];
//		        r.nextBytes(ivbytes);
//		        IvParameterSpec iv = new IvParameterSpec(ivbytes);
//		        byte[] encryptedMessage = crypto.encrypt(message.getBytes(), symmetricKey, iv);
//                ByteBuffer buf = ByteBuffer.wrap(encryptedMessage);
//                sc.write(ByteBuffer.wrap(iv.getIV()));
//                sc.write(buf);
				printPrompt = true;
            }
            sc.close();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }

    private static void writeSocket(String msg, SocketChannel client, SecureRandom r, Encryption crypto, SecretKey symmetricKey) throws IOException {
        byte ivbytes[] = new byte[16];
        r.nextBytes(ivbytes);
        IvParameterSpec iv = new IvParameterSpec(ivbytes);

        byte[] encryptedMessage = crypto.encrypt(msg.getBytes(), symmetricKey, iv);
        ByteBuffer[] bufs = {ByteBuffer.wrap(iv.getIV()), ByteBuffer.wrap(encryptedMessage)};
        client.write(bufs);
    }
}

class ClientThread extends Thread {
    SocketChannel sc;
    SecretKey key;
    Console cons;
    Encryption crypto;

    ClientThread(SocketChannel sc, SecretKey key) {
        this.sc = sc;
        this.key = key;
        cons = System.console();
        crypto = new Encryption();
    }

    public void run() {
        String recieved;
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
//                byte[] decryptedMessage = crypto.decrypt(bytes, key, iv);
//                byte[] a = new byte[buffer.remaining()];
//                buffer.get(a);
                recieved = new String(readSocket());
                System.out.println(recieved);
                if (recieved.equals("You have been kicked.") || recieved.equals("!shutdown")) {
                    System.exit(0);
                }
				System.out.print(">> ");
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
}
