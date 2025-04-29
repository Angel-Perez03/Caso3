// File: server/ServiceDelegate.java
package server;

import crypto.CryptoUtils;
import crypto.DHKeyExchange;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.spec.DHParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Servicio delegado que implementa el protocolo seguro y mide tiempos de operaciones criptográficas.
 */
public class ServiceDelegate implements Runnable {
    private final Socket socket;
    private final Map<Integer, ServiceInfo> services;
    private final PrivateKey priv;

    public ServiceDelegate(Socket socket, Map<Integer, ServiceInfo> services, PrivateKey priv) {
        this.socket = socket;
        this.services = services;
        this.priv = priv;
    }

    @Override
    public void run() {
        // Listas para recolectar tiempos (nanosegundos)
        List<Long> signTimes = new ArrayList<>();
        List<Long> encryptTableTimes = new ArrayList<>();
        List<Long> verifyReqTimes = new ArrayList<>();

        try (DataInputStream dis = new DataInputStream(socket.getInputStream());
             DataOutputStream dos = new DataOutputStream(socket.getOutputStream())) {

            // 1) Enviar HELLO
            dos.writeUTF("HELLO");
            System.out.println("[DEBUG][Srv] HELLO sent");

            // 2) Recibir y medir firma del reto
            int challenge = dis.readInt();
            System.out.println("[DEBUG][Srv] Challenge received: " + challenge);
            byte[] chalBytes = ByteBuffer.allocate(4).putInt(challenge).array();
            long t0 = System.nanoTime();
            byte[] sig1 = CryptoUtils.sign(chalBytes, priv);
            long signDuration = System.nanoTime() - t0;
            signTimes.add(signDuration);
            dos.writeInt(sig1.length);
            dos.write(sig1);
            System.out.println("[DEBUG][Srv] Signed challenge sent (" + (signDuration/1_000_000) + " ms)");

            // 3) Esperar OK del cliente
            String ok1 = dis.readUTF();
            System.out.println("[DEBUG][Cli] Client response: " + ok1);
            if (!"OK".equals(ok1)) return;

            // 4) Generar y enviar parámetros DH con firma
            DHParameterSpec dhSpec = DHKeyExchange.generateDHParams();
            var keyPair = DHKeyExchange.generateKeyPair(dhSpec);
            byte[] pBytes  = dhSpec.getP().toByteArray();
            byte[] gBytes  = dhSpec.getG().toByteArray();
            byte[] gxBytes = keyPair.getPublic().getEncoded();
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            buf.write(pBytes); buf.write(gBytes); buf.write(gxBytes);
            byte[] sig2 = CryptoUtils.sign(buf.toByteArray(), priv);
            dos.writeInt(pBytes.length);  dos.write(pBytes);
            dos.writeInt(gBytes.length);  dos.write(gBytes);
            dos.writeInt(gxBytes.length); dos.write(gxBytes);
            dos.writeInt(sig2.length);    dos.write(sig2);
            System.out.println("[DEBUG][Srv] DH params and signature sent");

            // 5) Esperar OK del cliente
            String ok2 = dis.readUTF();
            System.out.println("[DEBUG][Cli] Client response 2: " + ok2);
            if (!"OK".equals(ok2)) return;

            // 6) Recibir G^y
            int gyLen = dis.readInt();
            byte[] gyBytes = new byte[gyLen];
            dis.readFully(gyBytes);
            System.out.println("[DEBUG][Srv] Gy received");

            // 7) Derivar claves de sesión
            KeyFactory kf = KeyFactory.getInstance("DH");
            PublicKey clientPub = kf.generatePublic(new X509EncodedKeySpec(gyBytes));
            byte[] shared = DHKeyExchange.computeSharedSecret(keyPair.getPrivate(), clientPub);
            SecretKey aesKey  = CryptoUtils.deriveAESKey(shared);
            SecretKey hmacKey = CryptoUtils.deriveHMACKey(shared);
            System.out.println("[DEBUG][Srv] Session keys derived");

            // 8) Enviar tabla de servicios con nombre y medir cifrado
            StringBuilder sb = new StringBuilder();
            services.values().forEach(si -> sb.append(si.getId())
                                              .append(" – ")
                                              .append(si.getName())
                                              .append(" (")
                                              .append(si.getIp())
                                              .append(":")
                                              .append(si.getPort())
                                              .append(")\n"));
            byte[] tablePlain = sb.toString().getBytes("UTF-8");
            IvParameterSpec iv1 = CryptoUtils.generateIV();
            t0 = System.nanoTime();
            byte[] ctTable = CryptoUtils.encryptAES(tablePlain, aesKey, iv1);
            long encTableDuration = System.nanoTime() - t0;
            encryptTableTimes.add(encTableDuration);
            byte[] hmTable = CryptoUtils.generateHMAC(tablePlain, hmacKey);
            dos.writeInt(iv1.getIV().length); dos.write(iv1.getIV());
            dos.writeInt(ctTable.length);      dos.write(ctTable);
            dos.writeInt(hmTable.length);      dos.write(hmTable);
            System.out.println("[DEBUG][Srv] Encrypted table + HMAC sent (" + (encTableDuration/1_000_000) + " ms)");

            // 9) Recibir petición cifrada y medir verificación
            int iv2Len = dis.readInt(); byte[] iv2 = new byte[iv2Len]; dis.readFully(iv2);
            int ctReqLen = dis.readInt(); byte[] ctReq = new byte[ctReqLen]; dis.readFully(ctReq);
            int hmReqLen = dis.readInt(); byte[] hmReq = new byte[hmReqLen]; dis.readFully(hmReq);
            t0 = System.nanoTime();
            byte[] reqPlain = CryptoUtils.decryptAES(ctReq, aesKey, new IvParameterSpec(iv2));
            boolean reqOk = CryptoUtils.verifyHMAC(reqPlain, hmReq, hmacKey);
            long verifyReqDuration = System.nanoTime() - t0;
            verifyReqTimes.add(verifyReqDuration);
            System.out.println("[DEBUG][Srv] Request HMAC valid: " + reqOk + " (" + (verifyReqDuration/1_000_000) + " ms)");
            if (!reqOk) {
                dos.writeUTF("ERROR");
                return;
            }

            // 10) Procesar solicitud
            String reqStr = new String(reqPlain, "UTF-8");
            int sel = Integer.parseInt(reqStr.split(",")[0]);
            ServiceInfo info = services.getOrDefault(sel, new ServiceInfo(-1, "Unknown", "0.0.0.0", 0));
            String response = info.getIp() + "," + info.getPort();

            // 11) Enviar respuesta cifrada + HMAC + OK
            IvParameterSpec iv3 = CryptoUtils.generateIV();
            byte[] ctResp = CryptoUtils.encryptAES(response.getBytes("UTF-8"), aesKey, iv3);
            byte[] hmResp = CryptoUtils.generateHMAC(response.getBytes("UTF-8"), hmacKey);
            dos.writeInt(iv3.getIV().length); dos.write(iv3.getIV());
            dos.writeInt(ctResp.length);      dos.write(ctResp);
            dos.writeInt(hmResp.length);      dos.write(hmResp);
            dos.writeUTF("OK");
            System.out.println("[DEBUG][Srv] Response + HMAC + OK sent");

            // Mostrar promedios simples (ms con decimales)
            double avgSignMs     = signTimes.stream().mapToLong(Long::longValue).average().orElse(0.0) / 1_000_000.0;
            double avgEncTableMs = encryptTableTimes.stream().mapToLong(Long::longValue).average().orElse(0.0) / 1_000_000.0;
            double avgVerifyMs   = verifyReqTimes.stream().mapToLong(Long::longValue).average().orElse(0.0) / 1_000_000.0;

            System.out.printf(
                "[BENCH] avgSign=%.3f ms, avgEncTable=%.3f ms, avgVerifyReq=%.3f ms%n",
                avgSignMs, avgEncTableMs, avgVerifyMs
            );


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
