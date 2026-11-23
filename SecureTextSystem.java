import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

public class SecureTextSystem {
    private static final byte[] MAGIC = {'S', 'T', 'E', '1'};
    private static final int IV_LENGTH = 12;
    private static final int TAG_BITS = 128;
    private static final int MAX_DECOMPRESSED_BYTES = 100 * 1024 * 1024;
    private static final SecureRandom RANDOM = new SecureRandom();

    private static byte[] compress(byte[] data) {
        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION);
        deflater.setInput(data);
        deflater.finish();
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            while (!deflater.finished()) {
                int n = deflater.deflate(buffer);
                if (n == 0) throw new IllegalStateException("Compression stalled");
                out.write(buffer, 0, n);
            }
            return out.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        } finally {
            deflater.end();
        }
    }

    private static byte[] decompress(byte[] data) throws IOException {
        Inflater inflater = new Inflater();
        inflater.setInput(data);
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            while (!inflater.finished()) {
                int n;
                try {
                    n = inflater.inflate(buffer);
                } catch (DataFormatException e) {
                    throw new IOException("Invalid compressed data", e);
                }
                if (n > 0) {
                    if (out.size() + (long) n > MAX_DECOMPRESSED_BYTES)
                        throw new IOException("Decompressed data exceeds safety limit");
                    out.write(buffer, 0, n);
                } else if (inflater.needsInput() || inflater.needsDictionary()) {
                    throw new IOException("Incomplete compressed data");
                } else {
                    throw new IOException("Decompression stalled");
                }
            }
            if (inflater.getRemaining() != 0)
                throw new IOException("Unexpected trailing compressed data");
            return out.toByteArray();
        } finally {
            inflater.end();
        }
    }

    private static void encrypt(Path input, Path encrypted, Path keyFile)
            throws IOException, GeneralSecurityException {
        if (Files.exists(encrypted) || Files.exists(keyFile))
            throw new IOException("Output or key file already exists; choose new names");
        if (input.toAbsolutePath().normalize().equals(encrypted.toAbsolutePath().normalize()) ||
            input.toAbsolutePath().normalize().equals(keyFile.toAbsolutePath().normalize()) ||
            encrypted.toAbsolutePath().normalize().equals(keyFile.toAbsolutePath().normalize()))
            throw new IOException("Input, encrypted output and key paths must be distinct");

        byte[] original = Files.readAllBytes(input);
        long startCompression = System.nanoTime();
        byte[] compressed = compress(original);
        long endCompression = System.nanoTime();

        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256, RANDOM);
        SecretKey key = generator.generateKey();
        byte[] iv = new byte[IV_LENGTH];
        RANDOM.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
        cipher.updateAAD(MAGIC);
        long startEncryption = System.nanoTime();
        byte[] ciphertext = cipher.doFinal(compressed);
        long endEncryption = System.nanoTime();

        ByteBuffer output = ByteBuffer.allocate(MAGIC.length + iv.length + ciphertext.length);
        output.put(MAGIC).put(iv).put(ciphertext);
        Files.write(encrypted, output.array());
        Files.write(keyFile, key.getEncoded());

        System.out.println("Encryption successful: " + encrypted);
        System.out.println("Key saved separately: " + keyFile);
        printMetrics(original.length, compressed.length, output.array().length,
                endCompression - startCompression, endEncryption - startEncryption);
        System.out.println("Keep the .key file private. Anyone with it can decrypt the data.");
    }

    private static void decrypt(Path encrypted, Path recovered, Path keyFile)
            throws IOException, GeneralSecurityException {
        if (Files.exists(recovered))
            throw new IOException("Recovered output already exists; choose a new filename");
        if (recovered.toAbsolutePath().normalize().equals(encrypted.toAbsolutePath().normalize()) ||
            recovered.toAbsolutePath().normalize().equals(keyFile.toAbsolutePath().normalize()))
            throw new IOException("Recovered output must differ from encrypted file and key");
        byte[] bytes = Files.readAllBytes(encrypted);
        if (bytes.length < MAGIC.length + IV_LENGTH + 16)
            throw new IOException("Encrypted file is too short");
        if (!Arrays.equals(Arrays.copyOfRange(bytes, 0, MAGIC.length), MAGIC))
            throw new IOException("Invalid encrypted file format");
        byte[] keyBytes = Files.readAllBytes(keyFile);
        if (keyBytes.length != 32) throw new IOException("AES-256 key must be exactly 32 bytes");
        byte[] iv = Arrays.copyOfRange(bytes, MAGIC.length, MAGIC.length + IV_LENGTH);
        byte[] ciphertext = Arrays.copyOfRange(bytes, MAGIC.length + IV_LENGTH, bytes.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"),
                new GCMParameterSpec(TAG_BITS, iv));
        cipher.updateAAD(MAGIC);
        long startDecryption = System.nanoTime();
        byte[] compressed = cipher.doFinal(ciphertext);
        long endDecryption = System.nanoTime();
        long startDecompression = System.nanoTime();
        byte[] original = decompress(compressed);
        long endDecompression = System.nanoTime();
        Files.write(recovered, original);
        System.out.println("Recovered original data: " + recovered);
        System.out.printf("Decryption time: %.3f ms%n", (endDecryption - startDecryption) / 1e6);
        System.out.printf("Decompression time: %.3f ms%n", (endDecompression - startDecompression) / 1e6);
    }

    private static void printMetrics(int original, int compressed, int encrypted,
                                     long compressionNanos, long encryptionNanos) {
        System.out.println("Original size: " + original + " bytes");
        System.out.println("Compressed size: " + compressed + " bytes");
        System.out.println("Encrypted size: " + encrypted + " bytes (including header, IV, tag)");
        if (original > 0) {
            System.out.printf("Compression ratio: %.3f%n", (double) compressed / original);
            System.out.printf("Compression savings: %.2f%%%n", 100.0 * (original - compressed) / original);
            System.out.printf("Final file savings: %.2f%%%n", 100.0 * (original - encrypted) / original);
        }
        System.out.printf("Compression time: %.3f ms%n", compressionNanos / 1e6);
        System.out.printf("Encryption time: %.3f ms%n", encryptionNanos / 1e6);
    }

    public static void main(String[] args) {
        try (Scanner scanner = new Scanner(System.in)) {
            while (true) {
                System.out.println("\n=== Secure Text Compression and Encryption ===");
                System.out.println("1. Compress and encrypt file");
                System.out.println("2. Decrypt and decompress file");
                System.out.println("3. Exit");
                System.out.print("Choose: ");
                String choice = scanner.nextLine().trim();
                if (choice.equals("3")) break;
                if (!choice.equals("1") && !choice.equals("2")) {
                    System.out.println("Invalid choice");
                    continue;
                }
                try {
                    System.out.print("Input file path: ");
                    Path input = Path.of(scanner.nextLine().trim());
                    System.out.print("Output file path: ");
                    Path output = Path.of(scanner.nextLine().trim());
                    System.out.print("Key file path: ");
                    Path key = Path.of(scanner.nextLine().trim());
                    if (choice.equals("1")) encrypt(input, output, key);
                    else decrypt(input, output, key);
                } catch (AEADBadTagException e) {
                    System.out.println("Security verification failed: wrong key or tampered data");
                } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {
                    System.out.println("Error: " + e.getMessage());
                }
            }
        }
    }
}
