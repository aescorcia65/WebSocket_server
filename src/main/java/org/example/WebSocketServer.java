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
                    if (msg == null) break;
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

        private String readFrame() throws IOException {
            int b1 = in.read();
            if (b1 < 0) return null;
            int b2 = in.read();
            if (b2 < 0) return null;

            boolean masked = (b2 & 0x80) != 0;
            int len = b2 & 0x7F;

            if (len == 126) {
                byte[] ext = in.readNBytes(2);
                len = ByteBuffer.wrap(ext).getShort() & 0xFFFF;
            } else if (len == 127) {
                byte[] ext = in.readNBytes(8);
                len = (int)ByteBuffer.wrap(ext).getLong(); // assume <2^31
            }

            byte[] mask = masked ? in.readNBytes(4) : null;
            byte[] payload = in.readNBytes(len);

            if (masked) {
                for (int i = 0; i < payload.length; i++) {
                    payload[i] ^= mask[i % 4];
                }
            }

            return new String(payload, StandardCharsets.UTF_8);
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