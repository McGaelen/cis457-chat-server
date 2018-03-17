import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;

class Client {
    public static void main(String args[]) {
        Console cons = System.console();
        int portNum = Integer.parseInt(args[0]);
        String ipAddr = args[1];

        String message = "";
        try {
            SocketChannel sc = SocketChannel.open();
            sc.connect(new InetSocketAddress(ipAddr, portNum));
            ClientThread t = new ClientThread(sc);
            t.start();

            String username = cons.readLine("What username? ");
            username = "!rename " + username;
            sc.write(ByteBuffer.wrap(username.getBytes()));

            while (true) {
                message = cons.readLine("Enter your message: ");
                if (message.equals("quit")) {
                    break;
                }
                ByteBuffer buf = ByteBuffer.wrap(message.getBytes());
                sc.write(buf);
            }
            sc.close();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }
}

class ClientThread extends Thread {
    SocketChannel sc;
    Console cons;

    ClientThread(SocketChannel sc) {
        this.sc = sc;
        cons = System.console();
    }

    public void run() {
        String recieved;
        try {
            while (true) {
                ByteBuffer buffer = ByteBuffer.allocate(4096);
                sc.read(buffer);
                buffer.flip();
                byte[] a = new byte[buffer.remaining()];
                buffer.get(a);
                recieved = new String(a);
                System.out.println(recieved);
                if (recieved.equals("You have been kicked.")) {
                    System.exit(0);
                }
            }
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }
}
