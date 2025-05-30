package org.example;

import javax.crypto.KeyAgreement;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;

public class ECDSAvsEdDSAComparison {

    private static final int[] DATA_SIZES = {64, 1024, 10240, 102400};
    private static final int ITERATIONS = 100;

    public static void main(String[] args) throws Exception {
        System.out.println("ECDSA ve EdDSA Algoritmaları Karşılaştırması");
        System.out.println("==========================================");

        compareKeyGeneration();
        compareSignatureSize();
        comparePerformance();
    }

    /**
     * Her iki algoritma için anahtar üretim sürelerini karşılaştırır
     */
    private static void compareKeyGeneration() throws Exception {
        System.out.println("\n1. Anahtar Üretimi Karşılaştırması");
        System.out.println("--------------------------------");

        // ECDSA anahtar eğrileri
        String[] ecdsaCurves = {"secp256r1", "secp384r1", "secp521r1"};

        // EdDSA anahtar eğrileri
        String[] eddsaCurves = {"Ed25519", "Ed448"};

        System.out.println("| Algoritma | Eğri      | Anahtar Üretim Süresi (ms)| Özel Anahtar Boyutu (byte) | Genel Anahtar Boyutu (byte)|");
        System.out.println("|-----------|-----------|---------------------------|----------------------------|----------------------------|");

        // ECDSA anahtar üretimi
        for (String curve : ecdsaCurves) {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(curve);

            long startTime = System.nanoTime();
            keyGen.initialize(ecSpec);
            KeyPair keyPair = keyGen.generateKeyPair();
            long endTime = System.nanoTime();

            long keyGenTime = (endTime - startTime) / 1_000_000; // ms cinsinden

            byte[] privateKeyEncoded = keyPair.getPrivate().getEncoded();
            byte[] publicKeyEncoded = keyPair.getPublic().getEncoded();

            System.out.printf("| ECDSA     | %-8s | %-25d | %-26d | %-26d |%n",
                    curve, keyGenTime, privateKeyEncoded.length, publicKeyEncoded.length);
        }

        // EdDSA anahtar üretimi
        if (Security.getProvider("SunEC") != null) {
            for (String curve : eddsaCurves) {
                try {
                    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EdDSA");
                    NamedParameterSpec edSpec = new NamedParameterSpec(curve);

                    long startTime = System.nanoTime();
                    keyGen.initialize(edSpec);
                    KeyPair keyPair = keyGen.generateKeyPair();
                    long endTime = System.nanoTime();

                    long keyGenTime = (endTime - startTime) / 1_000_000; // ms cinsinden

                    byte[] privateKeyEncoded = keyPair.getPrivate().getEncoded();
                    byte[] publicKeyEncoded = keyPair.getPublic().getEncoded();

                    System.out.printf("| EdDSA     | %-8s | %-25d | %-26d | %-26d |%n",
                            curve, keyGenTime, privateKeyEncoded.length, publicKeyEncoded.length);
                } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
                    System.out.printf("| EdDSA     | %-8s | %-25s | %-26s | %-26s |%n",
                            curve, "Desteklenmiyor", "Desteklenmiyor", "Desteklenmiyor");
                }
            }
        }
    }

    /**
     * İmza boyutlarını karşılaştırır
     */
    private static void compareSignatureSize() throws Exception {
        System.out.println("\n2. İmza Boyutu Karşılaştırması");
        System.out.println("--------------------------------");

        System.out.println("| Algoritma | Eğri      | İmza Boyutu (byte)|");
        System.out.println("|-----------|-----------|-------------------|");

        // Test verisi
        byte[] testData = "Bu bir test verisidir.".getBytes(StandardCharsets.UTF_8);

        // ECDSA imza boyutları
        String[] ecdsaCurves = {"secp256r1", "secp384r1", "secp521r1"};
        for (String curve : ecdsaCurves) {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(new ECGenParameterSpec(curve));
            KeyPair keyPair = keyGen.generateKeyPair();

            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(keyPair.getPrivate());
            signature.update(testData);
            byte[] signatureBytes = signature.sign();

            System.out.printf("| ECDSA     | %-8s | %-17d |%n", curve, signatureBytes.length);
        }

        // EdDSA imza boyutları
        if (Security.getProvider("SunEC") != null) {
            String[] eddsaCurves = {"Ed25519", "Ed448"};
            for (String curve : eddsaCurves) {
                try {
                    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EdDSA");
                    keyGen.initialize(new NamedParameterSpec(curve));
                    KeyPair keyPair = keyGen.generateKeyPair();

                    // EdDSA için imza algoritması
                    Signature signature = Signature.getInstance(curve.equals("Ed25519") ?
                            "Ed25519" : "Ed448");
                    signature.initSign(keyPair.getPrivate());
                    signature.update(testData);
                    byte[] signatureBytes = signature.sign();

                    System.out.printf("| EdDSA     | %-8s | %-17d |%n", curve, signatureBytes.length);
                } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
                    System.out.printf("| EdDSA     | %-8s | %-17s |%n", curve, "Desteklenmiyor");
                }
            }
        }
    }

    /**
     * Her iki algoritma için performans karşılaştırması yapar
     */
    private static void comparePerformance() throws Exception {
        System.out.println("\n3. Performans Karşılaştırması");
        System.out.println("--------------------------------");

        // Her bir veri boyutu için test
        for (int dataSize : DATA_SIZES) {
            System.out.println("\nVeri Boyutu: " + dataSize + " bayt");
            System.out.println("| Algoritma | Eğri      | İmzalama Süresi (μs)| Doğrulama Süresi (μs)|");
            System.out.println("|-----------|-----------|---------------------|----------------------|");

            byte[] testData = new byte[dataSize];
            new SecureRandom().nextBytes(testData);

            // ECDSA performans testi
            String[] ecdsaCurves = {"secp256r1", "secp384r1", "secp521r1"};
            for (String curve : ecdsaCurves) {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
                keyGen.initialize(new ECGenParameterSpec(curve));
                KeyPair keyPair = keyGen.generateKeyPair();

                // İmzalama hızı
                Signature signatureSigner = Signature.getInstance("SHA256withECDSA");
                signatureSigner.initSign(keyPair.getPrivate());

                long startSign = System.nanoTime();
                for (int i = 0; i < ITERATIONS; i++) {
                    signatureSigner.update(testData);
                    byte[] signatureBytes = signatureSigner.sign();
                    // Her iterasyonda signature nesnesini sıfırla
                    if (i < ITERATIONS - 1) {
                        signatureSigner.initSign(keyPair.getPrivate());
                    }
                }
                long endSign = System.nanoTime();
                long signTime = (endSign - startSign) / ITERATIONS / 1_000; // ms cinsinden

                // İmza oluştur (doğrulama testleri için)
                signatureSigner.update(testData);
                byte[] signatureBytes = signatureSigner.sign();

                // Doğrulama hızı
                Signature signatureVerifier = Signature.getInstance("SHA256withECDSA");
                signatureVerifier.initVerify(keyPair.getPublic());

                long startVerify = System.nanoTime();
                for (int i = 0; i < ITERATIONS; i++) {
                    signatureVerifier.update(testData);
                    signatureVerifier.verify(signatureBytes);
                    // Her iterasyonda signature nesnesini sıfırla
                    if (i < ITERATIONS - 1) {
                        signatureVerifier.initVerify(keyPair.getPublic());
                    }
                }
                long endVerify = System.nanoTime();
                long verifyTime = (endVerify - startVerify) / ITERATIONS / 1_000; // ms cinsinden

                System.out.printf("| ECDSA     | %-8s | %-19d | %-20d |%n", curve, signTime, verifyTime);
            }

            // EdDSA performans testi
            if (Security.getProvider("SunEC") != null) {
                String[] eddsaCurves = {"Ed25519", "Ed448"};
                for (String curve : eddsaCurves) {
                    try {
                        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EdDSA");
                        keyGen.initialize(new NamedParameterSpec(curve));
                        KeyPair keyPair = keyGen.generateKeyPair();

                        // EdDSA için imza algoritması
                        String algoName = curve.equals("Ed25519") ? "Ed25519" : "Ed448";

                        // İmzalama hızı
                        Signature signatureSigner = Signature.getInstance(algoName);
                        signatureSigner.initSign(keyPair.getPrivate());

                        long startSign = System.nanoTime();
                        for (int i = 0; i < ITERATIONS; i++) {
                            signatureSigner.update(testData);
                            byte[] signatureBytes = signatureSigner.sign();
                            // Her iterasyonda signature nesnesini sıfırla
                            if (i < ITERATIONS - 1) {
                                signatureSigner.initSign(keyPair.getPrivate());
                            }
                        }
                        long endSign = System.nanoTime();
                        long signTime = (endSign - startSign) / ITERATIONS / 1_000; // ms cinsinden

                        // İmza oluştur (doğrulama testleri için)
                        signatureSigner.initSign(keyPair.getPrivate());
                        signatureSigner.update(testData);
                        byte[] signatureBytes = signatureSigner.sign();

                        // Doğrulama hızı
                        Signature signatureVerifier = Signature.getInstance(algoName);
                        signatureVerifier.initVerify(keyPair.getPublic());

                        long startVerify = System.nanoTime();
                        for (int i = 0; i < ITERATIONS; i++) {
                            signatureVerifier.update(testData);
                            signatureVerifier.verify(signatureBytes);
                            // Her iterasyonda signature nesnesini sıfırla
                            if (i < ITERATIONS - 1) {
                                signatureVerifier.initVerify(keyPair.getPublic());
                            }
                        }
                        long endVerify = System.nanoTime();
                        long verifyTime = (endVerify - startVerify) / ITERATIONS / 1_000; // ms cinsinden

                        System.out.printf("| EdDSA     | %-8s | %-19d | %-20d |%n", curve, signTime, verifyTime);
                    } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
                        System.out.printf("| EdDSA     | %-8s | %-19s | %-20s |%n",
                                curve, "Desteklenmiyor", "Desteklenmiyor");
                    }
                }
            }
        }
    }
}

/**
 * ECDSA ve EdDSA algoritmalarının temel işlevlerini gösteren örnek uygulama
 */
class SignatureExample {
    public static void main(String[] args) throws Exception {
        demonstrateECDSA();
        demonstrateEdDSA();
    }

    /**
     * ECDSA algoritmasının temel kullanımını gösterir
     */
    public static void demonstrateECDSA() throws Exception {
        System.out.println("\nECDSA Örnek Uygulaması");
        System.out.println("======================");

        // 1. Anahtar çifti oluşturma
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = keyGen.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        System.out.println("ECDSA anahtar çifti oluşturuldu (secp256r1)");
        System.out.println("Özel Anahtar: " + privateKey.getAlgorithm() + ", " + privateKey.getFormat());
        System.out.println("Genel Anahtar: " + publicKey.getAlgorithm() + ", " + publicKey.getFormat());

        // ECDSA anahtarı hakkında detay bilgi al
        ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
        int keySize = ecPublicKey.getParams().getCurve().getField().getFieldSize();
        System.out.println("Anahtar Boyutu: " + keySize + " bit");

        // 2. İmzalanacak veri
        String message = "Bu mesaj ECDSA ile imzalanacak.";
        byte[] data = message.getBytes(StandardCharsets.UTF_8);

        // 3. İmza oluşturma
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(data);
        byte[] signatureBytes = signature.sign();

        System.out.println("İmza Oluşturuldu:");
        System.out.println("İmza Boyutu: " + signatureBytes.length + " byte");
        System.out.println("İmza (Hex): " + bytesToHex(signatureBytes, 32));

        // 4. İmza doğrulama
        signature.initVerify(publicKey);
        signature.update(data);
        boolean verified = signature.verify(signatureBytes);

        System.out.println("İmza Doğrulama: " + (verified ? "Başarılı" : "Başarısız"));

        // 5. Yanlış veriyle doğrulama testi
        String alteredMessage = "Bu mesaj değiştirildi!";
        byte[] alteredData = alteredMessage.getBytes(StandardCharsets.UTF_8);

        signature.initVerify(publicKey);
        signature.update(alteredData);
        boolean failedVerify = signature.verify(signatureBytes);

        System.out.println("Değiştirilmiş Veri ile Doğrulama: " + (failedVerify ? "Başarılı (Beklenmedik!)" : "Başarısız (Beklenen)"));
    }

    /**
     * EdDSA algoritmasının temel kullanımını gösterir (Java 15+ gerektirir)
     */
    public static void demonstrateEdDSA() {
        try {
            System.out.println("\nEdDSA Örnek Uygulaması");
            System.out.println("======================");

            // 1. Anahtar çifti oluşturma (Ed25519)
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EdDSA");
            keyGen.initialize(new NamedParameterSpec("Ed25519"));
            KeyPair keyPair = keyGen.generateKeyPair();

            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            System.out.println("EdDSA anahtar çifti oluşturuldu (Ed25519)");
            System.out.println("Özel Anahtar: " + privateKey.getAlgorithm() + ", " + privateKey.getFormat());
            System.out.println("Genel Anahtar: " + publicKey.getAlgorithm() + ", " + publicKey.getFormat());
            System.out.println("Anahtar Boyutu: 256 bit (Ed25519 için sabit)");

            // 2. İmzalanacak veri
            String message = "Bu mesaj EdDSA ile imzalanacak.";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);

            // 3. İmza oluşturma
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(privateKey);
            signature.update(data);
            byte[] signatureBytes = signature.sign();

            System.out.println("İmza Oluşturuldu:");
            System.out.println("İmza Boyutu: " + signatureBytes.length + " byte");
            System.out.println("İmza (Hex): " + bytesToHex(signatureBytes, 32));

            // 4. İmza doğrulama
            signature.initVerify(publicKey);
            signature.update(data);
            boolean verified = signature.verify(signatureBytes);

            System.out.println("İmza Doğrulama: " + (verified ? "Başarılı" : "Başarısız"));

            // 5. Yanlış veriyle doğrulama testi
            String alteredMessage = "Bu mesaj değiştirildi!";
            byte[] alteredData = alteredMessage.getBytes(StandardCharsets.UTF_8);

            signature.initVerify(publicKey);
            signature.update(alteredData);
            boolean failedVerify = signature.verify(signatureBytes);

            System.out.println("Değiştirilmiş Veri ile Doğrulama: " + (failedVerify ? "Başarılı (Beklenmedik!)" : "Başarısız (Beklenen)"));

        } catch (Exception e) {
            System.out.println("\nEdDSA testi sırasında bir hata oluştu: " + e.getMessage());
        }
    }

    /**
     * Byte dizisini hex formatına dönüştürür
     */
    private static String bytesToHex(byte[] bytes, int limit) {
        StringBuilder sb = new StringBuilder();
        int displayLimit = Math.min(bytes.length, limit);
        for (int i = 0; i < displayLimit; i++) {
            sb.append(String.format("%02x", bytes[i]));
        }
        if (bytes.length > limit) {
            sb.append("... (toplam ").append(bytes.length).append(" byte)");
        }
        return sb.toString();
    }
}

/**
 * ECDSA vs EdDSA karşılaştırmasına ek olarak anahtar paylaşımı özelliğini gösteren sınıf
 */
class KeyExchangeImplementation {

    private static final int ITERATIONS = 100;

    public static void main(String[] args) throws Exception {
        System.out.println("\nAnahtar Paylaşımı Karşılaştırması");
        System.out.println("================================");

        compareKeyExchangeAlgorithms();

        System.out.println("\nAnahtar Paylaşımı Örnek Uygulaması");
        System.out.println("================================");

        demonstrateECDHKeyExchange();
        demonstrateX25519KeyExchange();
    }

    /**
     * ECDH ve X25519/X448 anahtar paylaşım algoritmaları karşılaştırması
     */
    private static void compareKeyExchangeAlgorithms() throws Exception {
        System.out.println("\nECDH ve X25519/X448 Algoritmaları Karşılaştırması");
        System.out.println("---------------------------------------------");

        // ECDH eğrileri
        String[] ecdhCurves = {"secp256r1", "secp384r1", "secp521r1"};

        // XDH eğrileri (X25519/X448)
        String[] xdhCurves = {"X25519", "X448"};

        System.out.println("| Algoritma | Eğri      | Anahtar Üretim (ms) | Paylaşım İşlemi (μs) | Ortak Anahtar Boyutu (byte) |");
        System.out.println("|-----------|-----------|---------------------|----------------------|----------------------------|");

        // ECDH algoritması için karşılaştırma
        for (String curve : ecdhCurves) {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(curve);

            // Anahtar üretim süresi
            long startKeyGen = System.nanoTime();
            keyGen.initialize(ecSpec);
            KeyPair aliceKeyPair = keyGen.generateKeyPair();
            KeyPair bobKeyPair = keyGen.generateKeyPair();
            long endKeyGen = System.nanoTime();
            long keyGenTime = (endKeyGen - startKeyGen) / 2_000_000; // ms cinsinden, 2 anahtar çifti

            // Anahtar paylaşım süresi
            long startExchange = System.nanoTime();

            for (int i = 0; i < ITERATIONS; i++) {
                // Alice tarafı
                KeyAgreement aliceKeyAgreement = KeyAgreement.getInstance("ECDH");
                aliceKeyAgreement.init(aliceKeyPair.getPrivate());
                aliceKeyAgreement.doPhase(bobKeyPair.getPublic(), true);
                byte[] aliceSharedSecret = aliceKeyAgreement.generateSecret();

                // Bob tarafı
                KeyAgreement bobKeyAgreement = KeyAgreement.getInstance("ECDH");
                bobKeyAgreement.init(bobKeyPair.getPrivate());
                bobKeyAgreement.doPhase(aliceKeyPair.getPublic(), true);
                byte[] bobSharedSecret = bobKeyAgreement.generateSecret();
            }

            long endExchange = System.nanoTime();
            long exchangeTime = (endExchange - startExchange) / ITERATIONS / 1_000; // μs cinsinden

            // Ortak gizli anahtarın boyutu
            KeyAgreement aliceKeyAgreement = KeyAgreement.getInstance("ECDH");
            aliceKeyAgreement.init(aliceKeyPair.getPrivate());
            aliceKeyAgreement.doPhase(bobKeyPair.getPublic(), true);
            byte[] sharedSecret = aliceKeyAgreement.generateSecret();

            System.out.printf("| ECDH      | %-8s | %-19d | %-20d | %-26d |%n",
                    curve, keyGenTime, exchangeTime, sharedSecret.length);
        }

        // X25519/X448 algoritması için karşılaştırma
        try {
            for (String curve : xdhCurves) {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("XDH");
                NamedParameterSpec xdhSpec = new NamedParameterSpec(curve);

                // Anahtar üretim süresi
                long startKeyGen = System.nanoTime();
                keyGen.initialize(xdhSpec);
                KeyPair aliceKeyPair = keyGen.generateKeyPair();
                KeyPair bobKeyPair = keyGen.generateKeyPair();
                long endKeyGen = System.nanoTime();
                long keyGenTime = (endKeyGen - startKeyGen) / 2_000_000; // ms cinsinden, 2 anahtar çifti

                // Anahtar paylaşım süresi
                long startExchange = System.nanoTime();

                for (int i = 0; i < ITERATIONS; i++) {
                    // Alice tarafı
                    KeyAgreement aliceKeyAgreement = KeyAgreement.getInstance("XDH");
                    aliceKeyAgreement.init(aliceKeyPair.getPrivate());
                    aliceKeyAgreement.doPhase(bobKeyPair.getPublic(), true);
                    byte[] aliceSharedSecret = aliceKeyAgreement.generateSecret();

                    // Bob tarafı
                    KeyAgreement bobKeyAgreement = KeyAgreement.getInstance("XDH");
                    bobKeyAgreement.init(bobKeyPair.getPrivate());
                    bobKeyAgreement.doPhase(aliceKeyPair.getPublic(), true);
                    byte[] bobSharedSecret = bobKeyAgreement.generateSecret();
                }

                long endExchange = System.nanoTime();
                long exchangeTime = (endExchange - startExchange) / ITERATIONS / 1_000; // μs cinsinden

                // Ortak gizli anahtarın boyutu
                KeyAgreement aliceKeyAgreement = KeyAgreement.getInstance("XDH");
                aliceKeyAgreement.init(aliceKeyPair.getPrivate());
                aliceKeyAgreement.doPhase(bobKeyPair.getPublic(), true);
                byte[] sharedSecret = aliceKeyAgreement.generateSecret();

                System.out.printf("| XDH       | %-8s | %-19d | %-20d | %-26d |%n",
                        curve, keyGenTime, exchangeTime, sharedSecret.length);
            }
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            System.out.println("| XDH       | Tüm Eğriler | Desteklenmiyor | Desteklenmiyor | Desteklenmiyor |");
            System.out.println("Not: XDH algoritması için Java 11+ ve güncellenmiş JCE gerekir.");
        }
    }

    /**
     * ECDH anahtar paylaşımı örneği
     */
    private static void demonstrateECDHKeyExchange() throws Exception {
        System.out.println("\nECDH Anahtar Paylaşımı Örneği");
        System.out.println("----------------------------");

        // 1. Alice ve Bob için anahtar çiftleri oluştur
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));

        KeyPair aliceKeyPair = keyGen.generateKeyPair();
        KeyPair bobKeyPair = keyGen.generateKeyPair();

        System.out.println("Alice ve Bob için ECDH anahtar çiftleri oluşturuldu (secp256r1)");

        // 2. Alice tarafı: Ortak gizli anahtar oluştur
        KeyAgreement aliceKeyAgreement = KeyAgreement.getInstance("ECDH");
        aliceKeyAgreement.init(aliceKeyPair.getPrivate());
        aliceKeyAgreement.doPhase(bobKeyPair.getPublic(), true);
        byte[] aliceSharedSecret = aliceKeyAgreement.generateSecret();

        // 3. Bob tarafı: Ortak gizli anahtar oluştur
        KeyAgreement bobKeyAgreement = KeyAgreement.getInstance("ECDH");
        bobKeyAgreement.init(bobKeyPair.getPrivate());
        bobKeyAgreement.doPhase(aliceKeyPair.getPublic(), true);
        byte[] bobSharedSecret = bobKeyAgreement.generateSecret();

        // 4. Sonuçları kontrol et
        System.out.println("Alice'in ortak gizli anahtarı: " + bytesToHex(aliceSharedSecret, 32));
        System.out.println("Bob'un ortak gizli anahtarı:   " + bytesToHex(bobSharedSecret, 32));
        System.out.println("Anahtarlar eşleşiyor mu? " + Arrays.equals(aliceSharedSecret, bobSharedSecret));
        System.out.println("Ortak gizli anahtar boyutu: " + aliceSharedSecret.length + " byte");
    }

    /**
     * X25519 anahtar paylaşımı örneği (Java 11+ gerektirir)
     */
    private static void demonstrateX25519KeyExchange() {
        try {
            System.out.println("\nX25519 Anahtar Paylaşımı Örneği");
            System.out.println("------------------------------");

            // 1. Alice ve Bob için anahtar çiftleri oluştur
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("XDH");
            keyGen.initialize(new NamedParameterSpec("X25519"));

            KeyPair aliceKeyPair = keyGen.generateKeyPair();
            KeyPair bobKeyPair = keyGen.generateKeyPair();

            System.out.println("Alice ve Bob için X25519 anahtar çiftleri oluşturuldu");

            // 2. Alice tarafı: Ortak gizli anahtar oluştur
            KeyAgreement aliceKeyAgreement = KeyAgreement.getInstance("XDH");
            aliceKeyAgreement.init(aliceKeyPair.getPrivate());
            aliceKeyAgreement.doPhase(bobKeyPair.getPublic(), true);
            byte[] aliceSharedSecret = aliceKeyAgreement.generateSecret();

            // 3. Bob tarafı: Ortak gizli anahtar oluştur
            KeyAgreement bobKeyAgreement = KeyAgreement.getInstance("XDH");
            bobKeyAgreement.init(bobKeyPair.getPrivate());
            bobKeyAgreement.doPhase(aliceKeyPair.getPublic(), true);
            byte[] bobSharedSecret = bobKeyAgreement.generateSecret();

            // 4. Sonuçları kontrol et
            System.out.println("Alice'in ortak gizli anahtarı: " + bytesToHex(aliceSharedSecret, 32));
            System.out.println("Bob'un ortak gizli anahtarı:   " + bytesToHex(bobSharedSecret, 32));
            System.out.println("Anahtarlar eşleşiyor mu? " + Arrays.equals(aliceSharedSecret, bobSharedSecret));
            System.out.println("Ortak gizli anahtar boyutu: " + aliceSharedSecret.length + " byte");

        } catch (Exception e) {
            System.out.println("\nX25519 anahtar paylaşımı sırasında bir hata oluştu: " + e.getMessage());
            System.out.println("Not: X25519 için Java 11+ ve güncellenmiş JCE gerekir.");
        }
    }

    /**
     * Byte dizisini hex formatına dönüştürür
     */
    private static String bytesToHex(byte[] bytes, int limit) {
        StringBuilder sb = new StringBuilder();
        int displayLimit = Math.min(bytes.length, limit);
        for (int i = 0; i < displayLimit; i++) {
            sb.append(String.format("%02x", bytes[i]));
        }
        if (bytes.length > limit) {
            sb.append("... (toplam ").append(bytes.length).append(" byte)");
        }
        return sb.toString();
    }
}