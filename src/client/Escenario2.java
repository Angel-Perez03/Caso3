package client;

import server.MainServer;

import java.util.concurrent.*;

public class Escenario2 {
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
        long t0 = System.nanoTime();
        long dt = System.nanoTime() - t0;

        // --- Escenario (ii): clientes concurrentes ---
        int[] pools = {4, 16, 32, 64};
        for (int nThreads : pools) {
            System.out.printf("%n=== Concurrentes: %d clientes ===%n", nThreads);
            ExecutorService exec = Executors.newFixedThreadPool(nThreads);
            t0 = System.nanoTime();
            for (int i = 0; i < nThreads; i++) {
                exec.submit(() -> new ClientDelegate(SERVER_IP, SERVER_PORT).run());
            }
            exec.shutdown();
            exec.awaitTermination(5, TimeUnit.MINUTES);
            dt = System.nanoTime() - t0;
            System.out.printf("Total concurrente (%d): %d ms%n", nThreads, dt / 1_000_000);
        }
    }
}
