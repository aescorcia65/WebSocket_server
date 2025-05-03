package org.example;

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.Base64;
import java.util.concurrent.CopyOnWriteArrayList;

public class WebSocketServer {
    private static final String MAGIC_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    private final List<Connection> connections = new CopyOnWriteArrayList<>();

    public static void main(String[] args) throws IOException {
        new WebSocketServer().start(8025);
    }

    public void start(int port) throws IOException {
        ServerSocket server = new ServerSocket(port);
        System.out.println("WebSocketServer listening on ws://localhost:" + port);
        while (true) {
            Socket client = server.accept();
            new Thread(new Connection(client)).start();
        }
    }

    private class Connection implements Runnable {
        private final Socket socket;
        private InputStream in;
        private OutputStream out;

        Connection(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try {
                in  = socket.getInputStream();
                out = socket.getOutputStream();
                doHandshake();
                connections.add(this);
                // read loop
                while (true) {
                    String msg = readFrame();
                    if (msg.equals("stop")) break;
                    broadcast(msg);
                }
            } catch (Exception e) {
                // e.printStackTrace();
            } finally {
                connections.remove(this);
                try { socket.close(); } catch (IOException ignored) {}
            }
        }

        private void doHandshake() throws Exception {
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String line;
            String key = null;
            // read HTTP headers
            while (!(line = reader.readLine()).isEmpty()) {
                if (line.toLowerCase().startsWith("sec-websocket-key:")) {
                    key = line.substring(18).trim();
                }
            }
            if (key == null) throw new IllegalStateException("No Sec-WebSocket-Key found");

            // compute accept
            String accept = Base64.getEncoder().encodeToString(
                    MessageDigest.getInstance("SHA-1")
                            .digest((key + MAGIC_GUID).getBytes(StandardCharsets.UTF_8))
            );

            // send response
            String resp =
                    "HTTP/1.1 101 Switching Protocols\r\n" +
                            "Upgrade: websocket\r\n" +
                            "Connection: Upgrade\r\n" +
                            "Sec-WebSocket-Accept: " + accept + "\r\n" +
                            "\r\n";
            out.write(resp.getBytes(StandardCharsets.UTF_8));
            out.flush();
        }

        public String readFrame() throws IOException {
            System.out.println("=== readFrame start ===");

            // 1) Read the first header byte (FIN, RSV, opcode)
            int b1 = in.read();
            System.out.printf("b1: %d (0x%02X) - FIN=%b, opcode=0x%X%n", b1, b1,
                    (b1 & 0x80) != 0, b1 & 0x0F);
            if (b1 < 0) return null;

            // 2) Read the second header byte (MASK bit + payload len)
            int b2 = in.read();
            System.out.printf("b2: %d (0x%02X) - MASK=%b, len bits=%d%n", b2, b2,
                    (b2 & 0x80) != 0, b2 & 0x7F);
            if (b2 < 0) return null;

            boolean masked = (b2 & 0x80) != 0;
            int len = b2 & 0x7F;

            // 3) Handle extended payload length
            if (len == 126) {
                byte[] ext = in.readNBytes(2);
                System.out.printf("Extended len (16-bit): %s%n", Arrays.toString(ext));
                len = ByteBuffer.wrap(ext).getShort() & 0xFFFF;
                System.out.println("Computed len (16-bit): " + len);
            } else if (len == 127) {
                byte[] ext = in.readNBytes(8);
                System.out.printf("Extended len (64-bit): %s%n", Arrays.toString(ext));
                len = (int) ByteBuffer.wrap(ext).getLong(); // assume <2^31
                System.out.println("Computed len (64-bit): " + len);
            } else {
                System.out.println("Payload len (no extension): " + len);
            }

            // 4) Read mask key if present
            byte[] mask = null;
            if (masked) {
                mask = in.readNBytes(4);
                System.out.printf("Mask key: %s%n", Arrays.toString(mask));
            }

            // 5) Read payload data
            byte[] payload = in.readNBytes(len);
            System.out.printf("Raw payload bytes: %s%n", Arrays.toString(payload));

            // 6) Unmask if needed
            if (masked) {
                for (int i = 0; i < payload.length; i++) {
                    payload[i] ^= mask[i % 4];
                }
                System.out.printf("Unmasked payload bytes: %s%n", Arrays.toString(payload));
            }

            // 7) Decode to UTF-8 string
            String result = new String(payload, StandardCharsets.UTF_8);
            System.out.println("Decoded payload: " + result);

            System.out.println("=== readFrame end ===");
            return result;
        }

        private void sendFrame(String message) {
            try {
                byte[] data = message.getBytes(StandardCharsets.UTF_8);
                int len = data.length;
                ByteArrayOutputStream frame = new ByteArrayOutputStream();
                frame.write(0x81); // FIN + text frame

                if (len <= 125) {
                    frame.write(len);
                } else if (len <= 0xFFFF) {
                    frame.write(126);
                    frame.write((len >> 8) & 0xFF);
                    frame.write(len & 0xFF);
                } else {
                    frame.write(127);
                    frame.write(ByteBuffer.allocate(8).putLong(len).array());
                }

                frame.write(data);
                out.write(frame.toByteArray());
                out.flush();
            } catch (IOException ignored) {}
        }

        private void broadcast(String msg) {
            System.out.println("Broadcasting: " + msg);
            for (Connection c : connections) {
                c.sendFrame(msg);
            }
        }
    }
}