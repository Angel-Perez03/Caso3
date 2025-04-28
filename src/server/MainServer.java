package server;

import crypto.CryptoUtils;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;

public class MainServer {
    public static final int PORT = 5000;

    public static void main(String[] args) throws Exception {
        // Carga clave privada del servidor
        PrivateKey priv = CryptoUtils.loadPrivateKey("keys/server_private.key");

        // Configura servicios disponibles
        Map<Integer, ServiceInfo> services = new HashMap<>();
        services.put(1, new ServiceInfo(1, "EstadoVuelo",   "192.168.1.10", 6001));
        services.put(2, new ServiceInfo(2, "Disponibilidad","192.168.1.11", 6002));
        services.put(3, new ServiceInfo(3, "CostoVuelo",    "192.168.1.12", 6003));

        // Inicia servidor y acepta conexiones
        try (ServerSocket ss = new ServerSocket(PORT)) {
            System.out.println("MainServer escuchando en puerto " + PORT);
            while (true) {
                // Espera cliente y delega en hilo nuevo
                Socket s = ss.accept();
                new Thread(new ServiceDelegate(s, services, priv)).start();
            }
        }
    }
}
