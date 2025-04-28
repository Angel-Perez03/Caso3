package keys;
import java.nio.file.*;
import java.security.*;

public class KeyGen {
  public static void main(String[] args) throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(1024);
    KeyPair kp = kpg.generateKeyPair();

    // Crea carpeta keys si no existe
    Files.createDirectories(Paths.get("keys"));

    // Guarda en DER puro
    Files.write(Paths.get("keys/server_private.key"), kp.getPrivate().getEncoded());
    Files.write(Paths.get("keys/server_public.key"),  kp.getPublic().getEncoded());
    System.out.println("¡Llaves generadas en keys/ !");
  }
}
