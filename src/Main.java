import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.*;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {
    private static byte[] iv = { 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8 };

    public static void main(String[] args)
            throws Exception {
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        String userMasterPassword;
        boolean isNewFile = false;
        HashMap<String, String> userPasswords;

        System.out.println("Provide the full path the file containing your passwords.");
        System.out.println("ex: /path/to/file.cpm\n");
        System.out.println("If the provided file does not exist one will be created for you");

        Scanner scanner = new Scanner(System.in);
        String filePath = scanner.nextLine();
        File file = new File(filePath);
        if (!file.exists()) {
            isNewFile = true;
            file.createNewFile();
            System.out.println("New file has been created");
        }

        System.out.println("\nWhat is your master password?");
        userMasterPassword = scanner.nextLine();
        if (!isNewFile) {
            System.out.println("\nLoading your passwords...");
            try {
                userPasswords = readUserPasswords(file, userMasterPassword, ivParameterSpec);
            } catch(Exception e) {
                System.out.println("An error occurred reading your passwords, exiting application.");
                return;
            }
            System.out.println("Passwords loaded successfully");
        } else {
            userPasswords = new HashMap<>();
        }

        int cmd = 0;
        while (cmd != 4) {
            System.out.println("\nPlease choose a command:");
            System.out.println("\t1. View your current password list");
            System.out.println("\t2. Add a password");
            System.out.println("\t3. Remove a password");
            System.out.println("\t4. Exit a save your passwords to " + filePath);

            cmd = Integer.parseInt(scanner.nextLine());
            System.out.println();
            switch (cmd) {
                case 1:
                    viewPasswordList(userPasswords);
                    break;
                case 2:
                    addPasswordToList(userPasswords, scanner);
                    break;
                case 3:
                    removePasswordFromList(userPasswords, scanner);
                    break;
                case 4:
                    exitAndSavePasswordsToFile(userPasswords, file, isNewFile, userMasterPassword, ivParameterSpec);
                    System.out.println("Exiting application");
                    break;
                default:
                    break;
            }
        }
    }

    private static void viewPasswordList(HashMap<String, String> userPasswords) {
        System.out.println("Password List:");
        userPasswords.keySet()
                .forEach(key -> System.out.printf("\t%s -> %s%n", key, userPasswords.get(key)));
    }

    private static void addPasswordToList(HashMap<String, String> userPasswords, Scanner scanner) {
        System.out.println("What is the account name?");
        String account = scanner.nextLine();
        System.out.println("What is the account password?");
        String accountPassword = scanner.nextLine();
        userPasswords.put(account, accountPassword);
        System.out.println("Password added successfully");
    }

    private static void removePasswordFromList(HashMap<String, String> userPasswords, Scanner scanner) {
        viewPasswordList(userPasswords);
        System.out.println("What is the account name to remove?");
        String account = scanner.nextLine();
        userPasswords.remove(account);
        System.out.println("Password removed successfully");
    }

    private static void exitAndSavePasswordsToFile(HashMap<String, String> userPasswords, File file, boolean isNewFile,
                                                   String masterPassword, IvParameterSpec ivParameterSpec)
            throws Exception {
        System.out.println("Saving user passwords...");
        SecretKey secretKey = getKeyFromPassword(masterPassword);

        if (!isNewFile) {
            file.delete();
            file.createNewFile();
        }

        BufferedWriter writer = new BufferedWriter(new FileWriter(file));
        for (String key : userPasswords.keySet()) {
            String passwordEntry = String.format("%s,%s", key, userPasswords.get(key));
            String encryptedEntry = encrypt(passwordEntry, secretKey, ivParameterSpec);
            writer.write(encryptedEntry);
            writer.newLine();
        }

        writer.close();
        System.out.println("User passwords save successfully!");
    }

    private static HashMap<String, String> readUserPasswords(File file, String masterPassword, IvParameterSpec ivParameterSpec)
            throws Exception {
        SecretKey secretKey = getKeyFromPassword(masterPassword);
        HashMap<String, String> userPasswords = new HashMap<>();

        BufferedReader reader = new BufferedReader(new FileReader(file));
        String line;
        while ((line = reader.readLine()) != null) {
            List<String> lineSplit = Arrays.asList(decrypt(line, secretKey, ivParameterSpec).split(",")); // github,password
            userPasswords.put(lineSplit.get(0), lineSplit.get(1));
        }

        reader.close();
        return userPasswords;
    }

    private static SecretKey getKeyFromPassword(String password)
            throws InvalidKeySpecException, NoSuchAlgorithmException {

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), "salt".getBytes(), 65536, 256);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec)
                .getEncoded(), "AES");
        return secret;
    }

    private static String decrypt(String cipherText, SecretKey key,
                                  IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder()
                .decode(cipherText));
        return new String(plainText);
    }

    private static String encrypt(String input, SecretKey key,
                                 IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder()
                .encodeToString(cipherText);
    }
}