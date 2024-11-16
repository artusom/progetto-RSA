package it.artusom;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;
import java.util.StringTokenizer;
import java.util.Vector;

/**
 * Classe principale per la crittografia RSA. Implementa la generazione di chiavi,
 * la crittografia e la decrittografia di un messaggio.
 */
public class RSA {
    private static final Logger logger = LogManager.getLogger(RSA.class);
    private static final String TOKEN = ";"; // Separatore per i caratteri crittografati


    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        logger.info("Avvio dell'applicazione RSA.");
        logger.info("Richiesta dell'input da parte dell'utente.");

        System.out.print("Inserisci il messaggio da criptare: ");
        String stringa = scanner.nextLine();
        logger.debug("Messaggio inserito: {}", stringa);

        rsaEncrypt(stringa);

        scanner.close();
        logger.info("Applicazione terminata.");
    }


    /**
     * 
     * @param stringa messaggio da crittografare
     */
    private static void rsaEncrypt(String stringa) {
        Random rng = new Random();

        BigInteger p = BigInteger.probablePrime(16, rng); //16 bit
        BigInteger q = BigInteger.probablePrime(16, rng);

        logger.debug("Numeri primi generati: p={}, q={}", p, q);
        BigInteger n = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)); //funzione di Eulero per trovare c.pr. [φ(n) = (p-1) * (q-1)]
        logger.debug("Modulo n: {}, φ(n): {}", n, phi);

        BigInteger e;
        do {
            e = new BigInteger(phi.bitLength(), rng); //restituisce n. di bit per rappresentare n. binario
        } while (e.compareTo(BigInteger.ONE) <= 0 || e.compareTo(phi) >= 0 || !e.gcd(phi).equals(BigInteger.ONE));  //finchè il divisore comune è solo 1
        logger.debug("Esponente pubblico scelto: e={}", e);

        BigInteger d = e.modInverse(phi);     //inverso rspetto a φ(n)
        logger.debug("Esponente privato calcolato: d={}", d);

        logger.info("Avvio della crittografia del messaggio.");
        String encrypted = encrypt(stringa, e, n);
        logger.info("Messaggio crittografato: {}", encrypted);

        logger.info("Avvio della decrittografia del messaggio.");
        decrypt(encrypted, d, n);
    }


    /**
     * 
     * @param stringa messaggio da crittografare
     * @param e esponente pubblico
     * @param n modulo, prodotto di due numeri primi
     * @return messaggio crittografato
     */
    private static String encrypt(String stringa, BigInteger e, BigInteger n) {
        Vector<BigInteger> intVector = new Vector<>();
        StringBuilder intList = new StringBuilder();

        
        for (char character : stringa.toCharArray()) {
            BigInteger c = BigInteger.valueOf((int) character).modPow(e, n);   //(m^e) % n
            intVector.add(c);
            intList.append(c).append(TOKEN);
        }

        logger.debug("Vettore crittografato: {}", intVector);
        return intList.toString();
    }


    /**
     * 
     * @param stringa messaggio cifrato
     * @param d esponente privato
     * @param n 
     */
    private static void decrypt(String stringa, BigInteger d, BigInteger n) {
        StringTokenizer tokenizer = new StringTokenizer(stringa, TOKEN);
        StringBuilder decryptedText = new StringBuilder();

        while (tokenizer.hasMoreTokens()) {
            BigInteger c = new BigInteger(tokenizer.nextToken());
            BigInteger m = c.modPow(d, n);    //(c^d) % n
            decryptedText.append((char) m.intValue());
        }

        logger.info("Messaggio decrittato: {}", decryptedText);
    }
}