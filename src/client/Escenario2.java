// File: client/Escenario2.java
package client;

import server.MainServer;

import java.util.Random;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;



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

        // 1) Pequeña pausa para que el servidor escuche el puerto
        Thread.sleep(1000);

        // 2) Preguntar al usuario cuántos clientes concurrentes desea lanzar
        Scanner sc = new Scanner(System.in);
        System.out.print("¿Cuántos clientes concurrentes deseas lanzar? ");
        int nClients = sc.nextInt();
        sc.close();

        System.out.printf("%n=== Escenario concurrente: %d clientes ===%n", nClients);

        // 3) Crear pool de hilos y lanzar cada delegado con un servicio al azar
        ExecutorService exec = Executors.newFixedThreadPool(nClients);
        Random rnd = new Random();

        for (int i = 0; i < nClients; i++) {
            exec.submit(() -> {
                // Seleccionar ID de servicio aleatorio entre 1 y 3
                int serviceId = rnd.nextInt(3) + 1;
                System.out.println("[DEBUG] Client for service ID: " + serviceId);
                new ClientDelegate(SERVER_IP, SERVER_PORT, serviceId).run();
            });
        }

        // 4) Esperar a que terminen todos los clientes
        exec.shutdown();
        if (!exec.awaitTermination(5, TimeUnit.MINUTES)) {
            System.err.println("Timeout esperando que terminen los clientes");
        }

        System.out.println("=== Fin del escenario concurrente ===");
    }
}
