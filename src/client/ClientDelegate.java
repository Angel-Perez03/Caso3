package client;

import crypto.CryptoUtils;
import crypto.DHKeyExchange;

import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;
import java.util.Scanner;

/**
 * Ejecuta el protocolo seguro completo: handshake RSA, Diffie-Hellman,
 * recibe y muestra la tabla de servicios, permite elegir un servicio,
 * envía la solicitud y muestra la respuesta.
 */
public class ClientDelegate implements Runnable {
    private final String serverIp;
    private final int serverPort;
    private final int serviceId;

    public ClientDelegate(String serverIp, int serverPort, int serviceId) {
        this.serverIp = serverIp;
        this.serverPort = serverPort;   
        this.serviceId = serviceId;
        
    }

    public ClientDelegate(String serverIp, int serverPort) {
        this.serverIp = serverIp;
        this.serverPort = serverPort;
        this.serviceId = -1; // Default value for serviceId
    }

    @Override
    public void run() {
        try {
            // 1. Cargar clave pública del servidor
            PublicKey serverPub = CryptoUtils.loadPublicKey("keys/server_public.key");

            try (Socket sock = new Socket(serverIp, serverPort);
                 DataOutputStream dos = new DataOutputStream(sock.getOutputStream());
                 DataInputStream dis = new DataInputStream(sock.getInputStream())) {

                // Paso 1: HELLO
                String hello = dis.readUTF();
                System.out.println("[DEBUG][Cli] HELLO received: " + hello);

                // Paso 2: reto + firma
                int challenge = new Random().nextInt();
                System.out.println("[DEBUG][Cli] Challenge sent: " + challenge);
                dos.writeInt(challenge);
                int sigLen1 = dis.readInt();
                byte[] sig1 = new byte[sigLen1];
                dis.readFully(sig1);
                boolean ok1 = CryptoUtils.verifySignature(
                    ByteBuffer.allocate(4).putInt(challenge).array(), sig1, serverPub);
                System.out.println("[DEBUG][Cli] Challenge sig valid: " + ok1);
                if (!ok1) return;
                dos.writeUTF("OK");
                System.out.println("[DEBUG][Cli] Sent OK");

                // Paso 3: parámetros DH + firma
                int pLen = dis.readInt(); byte[] pBytes = new byte[pLen]; dis.readFully(pBytes);
                int gLen = dis.readInt(); byte[] gBytes = new byte[gLen]; dis.readFully(gBytes);
                int gxLen = dis.readInt(); byte[] gxBytes = new byte[gxLen]; dis.readFully(gxBytes);
                int sigLen2 = dis.readInt(); byte[] sig2 = new byte[sigLen2]; dis.readFully(sig2);
                ByteBuffer dhBuf = ByteBuffer.allocate(pBytes.length + gBytes.length + gxBytes.length);
                dhBuf.put(pBytes).put(gBytes).put(gxBytes);
                boolean ok2 = CryptoUtils.verifySignature(dhBuf.array(), sig2, serverPub);
                System.out.println("[DEBUG][Cli] DH params sig valid: " + ok2);
                if (!ok2) return;
                dos.writeUTF("OK");
                System.out.println("[DEBUG][Cli] Sent OK");

                // Paso 4: envío G^y
                DHParameterSpec dhSpec = new DHParameterSpec(
                    new java.math.BigInteger(pBytes), new java.math.BigInteger(gBytes)
                );
                var kp = DHKeyExchange.generateKeyPair(dhSpec);
                byte[] gyBytes = kp.getPublic().getEncoded();
                dos.writeInt(gyBytes.length); dos.write(gyBytes);
                System.out.println("[DEBUG][Cli] Gy sent");

                // Paso 5: derivar claves
                KeyFactory kf = KeyFactory.getInstance("DH");
                PublicKey srvPubKey = kf.generatePublic(new X509EncodedKeySpec(gxBytes));
                byte[] shared = DHKeyExchange.computeSharedSecret(kp.getPrivate(), srvPubKey);
                SecretKey aesKey = CryptoUtils.deriveAESKey(shared);
                SecretKey hmacKey = CryptoUtils.deriveHMACKey(shared);
                System.out.println("[DEBUG][Cli] Session keys derived");

                // Paso 6: recibir tabla cifrada + HMAC
                int ivLen = dis.readInt(); byte[] iv = new byte[ivLen]; dis.readFully(iv);
                int ctLen = dis.readInt(); byte[] ct = new byte[ctLen]; dis.readFully(ct);
                int hmLen = dis.readInt(); byte[] hm = new byte[hmLen]; dis.readFully(hm);
                byte[] tablePlain = CryptoUtils.decryptAES(ct, aesKey, new IvParameterSpec(iv));
                boolean tableOk = CryptoUtils.verifyHMAC(tablePlain, hm, hmacKey);
                System.out.println("[DEBUG][Cli] Table HMAC valid: " + tableOk);
                System.out.println("Servicios disponibles:");
                System.out.println(new String(tablePlain, "UTF-8"));

                // Paso 7: pedir al usuario
                int svcId;
                if (serviceId != -1) {
                    svcId = serviceId;
                } else {
                    System.out.print("Ingresa ID de servicio: ");
                    Scanner sc = new Scanner(System.in);
                    svcId = sc.nextInt();
                }

                // Paso 8: enviar solicitud cifrada + HMAC
                String request = svcId + "," + sock.getLocalAddress().getHostAddress();
                IvParameterSpec iv2 = CryptoUtils.generateIV();
                byte[] ctReq = CryptoUtils.encryptAES(request.getBytes("UTF-8"), aesKey, iv2);
                byte[] hmReq = CryptoUtils.generateHMAC(request.getBytes("UTF-8"), hmacKey);
                dos.writeInt(iv2.getIV().length); dos.write(iv2.getIV());
                dos.writeInt(ctReq.length); dos.write(ctReq);
                dos.writeInt(hmReq.length); dos.write(hmReq);
                System.out.println("[DEBUG][Cli] Request sent with HMAC");

                // Paso 9: recibir respuesta cifrada + HMAC
                int iv3Len = dis.readInt(); byte[] iv3 = new byte[iv3Len]; dis.readFully(iv3);
                int ct3Len = dis.readInt(); byte[] ct3 = new byte[ct3Len]; dis.readFully(ct3);
                int hm3Len = dis.readInt(); byte[] hm3 = new byte[hm3Len]; dis.readFully(hm3);
                byte[] respPlain = CryptoUtils.decryptAES(ct3, aesKey, new IvParameterSpec(iv3));
                boolean respOk = CryptoUtils.verifyHMAC(respPlain, hm3, hmacKey);
                System.out.println("[DEBUG][Cli] Response HMAC valid: " + respOk);
                System.out.println("Respuesta: " + new String(respPlain, "UTF-8"));

                // Paso 10: estado final
                String finalOK = dis.readUTF();
                System.out.println("[DEBUG][Cli] Final OK: " + finalOK);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}