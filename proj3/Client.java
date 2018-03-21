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
            sc.write(ByteBuffer.wrap(username.getBytes()));

			System.out.print(">> ");
            while (true) {
				if (printPrompt) {
					System.out.print(">> ");
				}
				message = cons.readLine();
                if (message.equals("!quit")) {
                    break;
                }

                byte ivbytes[] = new byte[16];
		        r.nextBytes(ivbytes);
		        IvParameterSpec iv = new IvParameterSpec(ivbytes);
		        byte[] encryptedMessage = crypto.encrypt(message.getBytes(), symmetricKey, iv);
                ByteBuffer buf = ByteBuffer.wrap(encryptedMessage);
                sc.write(ByteBuffer.wrap(iv.getIV()));
                sc.write(buf);
				printPrompt = true;
            }
            sc.close();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }
}

class ClientThread extends Thread {
    SocketChannel sc;
    SecretKey key;
    Console cons;

    ClientThread(SocketChannel sc, SecretKey key) {
        this.sc = sc;
        this.key = key;
        cons = System.console();
    }

    public void run() {
        String recieved;
        Encryption crypto = new Encryption();
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
                recieved = new String(decryptedMessage);
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
}
