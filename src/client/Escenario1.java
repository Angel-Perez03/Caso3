package client;

import server.MainServer;

public class Escenario1 {
    private static final String SERVER_IP   = "127.0.0.1";
    private static final int    SERVER_PORT = 5000;

    public static void main(String[] args) throws Exception {
        // 0) Arrancar servidor en background
        Thread srv = new Thread(() -> {
            try {
                MainServer.main(new String[]{});
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        srv.setDaemon(true);
        srv.start();

        // 1) Pequeña pausa para que el servidor haga listen()
        Thread.sleep(1000);

        // --- Escenario (i): 32 consultas secuenciales ---
        System.out.println("=== Secuencial: 32 consultas ===");
        long t0 = System.nanoTime();
        for (int i = 0; i < 32; i++) {
            new ClientDelegate(SERVER_IP, SERVER_PORT).run();
        }
        long dt = System.nanoTime() - t0;
        System.out.printf("Total secuencial: %d ms%n", dt / 1_000_000);

    }
}
