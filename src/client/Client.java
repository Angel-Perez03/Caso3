package client;

/**
 * Clase principal que inicia el protocolo seguro.
 */
public class Client {
    public static void main(String[] args) {
        // Ejecuta todo el flujo en el mismo hilo 
        new ClientDelegate("127.0.0.1", 5000).run();
    }
}