import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

class Server {
    public static HashMap<String, SocketChannel> userSockets;
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
					SocketChannel sc = (SocketChannel)pair.getValue();
					try {
						sc.write(ByteBuffer.wrap("!shutdown".getBytes()));
						sc.close();
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
            while (true) {
                sc = c.accept();
                userSockets.put("", sc);
                TcpServerThread t = new TcpServerThread(sc);
                t.start();
            }
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }
}

class TcpServerThread extends Thread {
    SocketChannel sc;
    Console cons;
    String username;

    TcpServerThread(SocketChannel sc) {
        this.sc = sc;
        cons = System.console();
        username = "";
    }

    public void run() {
        String command;

        try {
            while (true) {
                ByteBuffer buffer = ByteBuffer.allocate(4096);
                sc.read(buffer);
                buffer.flip();
                byte[] a = new byte[buffer.remaining()];
                buffer.get(a);
                command = new String(a);
				if (command.equals("")) {
					continue;
				}

                System.out.println("Got from client " + username + ": " + command);
                final String[] args;
                args = command.split(" ");

                if (args[0].equals("!rename")) {
                    username = args[1];

                    HashMap<String, SocketChannel> userSocketsCopy = new HashMap<>(Server.userSockets);
                    userSocketsCopy.forEach( (name, sc) -> {
                        if (this.sc.equals(sc)) {
                            Server.userSockets.remove(name);
                            Server.userSockets.put(args[1], sc);
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
                        sc.write(ByteBuffer.wrap("Naughty naughty! Bad Client!".getBytes()));
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
                    	Server.userSockets.get(args[0]).write(ByteBuffer.wrap((username + ": " + command.substring(command.indexOf(' ') + 1)).getBytes()));
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
