package crypto;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class DHKeyExchange {
    // Genera parámetros DH de 1024 bits
    public static DHParameterSpec generateDHParams() throws Exception {
        AlgorithmParameterGenerator gen = AlgorithmParameterGenerator.getInstance("DH");
        gen.init(1024);
        AlgorithmParameters params = gen.generateParameters();
        return params.getParameterSpec(DHParameterSpec.class);
    }

    // Crea par de claves DH con los parámetros dados
    public static KeyPair generateKeyPair(DHParameterSpec spec) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        kpg.initialize(spec);
        return kpg.generateKeyPair();
    }

    // Calcula el secreto compartido DH
    public static byte[] computeSharedSecret(PrivateKey priv, PublicKey pub) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(priv);
        ka.doPhase(pub, true);
        return ka.generateSecret();
    }
}
