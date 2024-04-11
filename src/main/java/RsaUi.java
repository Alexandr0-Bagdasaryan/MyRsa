import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.math.BigInteger;
import java.util.*;
import java.util.List;
import java.util.regex.Pattern;

public class RsaUi extends JFrame {
    private JTextField pField;
    private JTextField qField;
    private JTextField publicField;
    private JTextField privateField;
    private JTextArea messageArea;
    private JLabel label;
    private JButton encryptBtn;
    private JButton decryptBtn;
    private JTextArea analyzieArea;
    private JPanel MainPanel;
    private JButton keyGenBtn;
    private JTextField messageField;
    private JTextField encryptField;
    private JTextField decryptField;
    private JButton clearBtn;


    private BigInteger exp;
    private BigInteger mod;
    private BigInteger phi;
    private String publicKey;
    private String privateKey;
    private BigInteger d;
    private List<BigInteger>    encryptList = new ArrayList<>();
    private List<BigInteger> decryptList = new ArrayList<>();

    // Создаем Map для хранения букв и их номеров
    Map<Character, Integer> alphabetMap = new HashMap<>();




    // Метод для преобразования строки сообщения в последовательность чисел
    public static BigInteger[] convertMessageToNumbers(String message) {
        BigInteger[] numbers = new BigInteger[message.length()];
        for (int i = 0; i < message.length(); i++) {
            char letter = message.charAt(i);
            // Преобразование буквы в номер в русском алфавите
            int number = (int) letter - (int) 'а' + 1;
            numbers[i] = BigInteger.valueOf(number);
        }
        return numbers;
    }

    // Метод для преобразования последовательности чисел обратно в строку сообщения
    public static String convertNumbersToMessage(BigInteger[] numbers) {
        StringBuilder message = new StringBuilder();
        for (BigInteger number : numbers) {
            // Преобразование номера в букву русского алфавита
            char letter = (char) (number.intValue() + 'а' - 1);
            message.append(letter);
        }
        return message.toString();
    }

    // Метод для шифрования сообщения с использованием открытого ключа RSA
    public static BigInteger[] encryptMessage(BigInteger[] numbers, BigInteger e, BigInteger n) {
        BigInteger[] encryptedNumbers = new BigInteger[numbers.length];
        for (int i = 0; i < numbers.length; i++) {
            // Шифрование: number^e mod n
            encryptedNumbers[i] = numbers[i].modPow(e, n);
        }
        return encryptedNumbers;
    }

    // Метод для расшифрования зашифрованного сообщения с использованием закрытого ключа RSA
    public static BigInteger[] decryptMessage(BigInteger[] encryptedNumbers, BigInteger d, BigInteger n) {
        BigInteger[] decryptedNumbers = new BigInteger[encryptedNumbers.length];
        for (int i = 0; i < encryptedNumbers.length; i++) {
            decryptedNumbers[i] = encryptedNumbers[i].modPow(d, n);
        }
        return decryptedNumbers;
    }

    public void alphabetGen(){
        String alphabet = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя";
        if(alphabetMap.isEmpty()) {
            for (int i = 0; i < alphabet.length(); i++) {
                char letter = alphabet.charAt(i);
                // Нумерация начинается с 1, поэтому добавляем 1 к индексу
                alphabetMap.put(letter, i + 1);
            }
        }
    }


    private static BigInteger calculateEulerFunction(BigInteger p, BigInteger q) {
        return p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    }

    // Метод для выбора открытой экспоненты e
    private static BigInteger choosePublicExponent(BigInteger phi) {
        BigInteger e = BigInteger.valueOf(65537); // Обычно используется простое число Ферма 65537
        while (phi.gcd(e).intValue() > 1) {
            e = e.add(BigInteger.ONE);
        }
        return e;
    }

    // Метод для вычисления закрытой экспоненты d
    private static BigInteger calculatePrivateExponent(BigInteger e, BigInteger phi) {
        return e.modInverse(phi);
    }






    public RsaUi(){

        setTitle("RSA");
        setContentPane(MainPanel);
        setSize(300,300);
        setVisible(true);
        keyGenBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                alphabetGen();
                if((!pField.getText().isEmpty() &&!qField.getText().isEmpty())&&
                        (Pattern.matches("\\d+", pField.getText()) && (Pattern.matches("\\d+", pField.getText())))){
                    BigInteger p= BigInteger.valueOf(Integer.parseInt(pField.getText()));
                    BigInteger q= BigInteger.valueOf(Integer.parseInt(qField.getText()));
                    if(p.isProbablePrime(100)&&q.isProbablePrime(100));{
                        mod=p.multiply(q);
                        analyzieArea.append("Анализ начался\nmod:"+mod+"\n");
                        phi=calculateEulerFunction(p,q);
                        analyzieArea.append("phi:"+phi+"\n");
                        exp=choosePublicExponent(phi);
                        analyzieArea.append("e:"+exp+"\n");
                        publicKey=String.format("%s,%d", exp, mod);
                        publicField.setText(publicKey);
                        d=calculatePrivateExponent(exp,phi);
                        analyzieArea.append("d:"+d+"\n");
                        privateKey=String.format("%s,%d", d, mod);
                        privateField.setText(privateKey);
                        keyGenBtn.setForeground(Color.green);
                    }
                }
                else{
                    keyGenBtn.setForeground(Color.red);
                }
            }
        });

        encryptBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if(!messageField.getText().isEmpty()){
                    analyzieArea.append("Зашифровонное сообщение:\n");
                    BigInteger[] numbers = convertMessageToNumbers(messageField.getText());
                    BigInteger[] encryptedNumbers = encryptMessage(numbers, exp, mod);
                    analyzieArea.append("Резерв:\n");
                    String encrypt="";
                    for(int i=0;i<encryptedNumbers.length;i++){
                        analyzieArea.append(encryptedNumbers[i]+" ");
                        encrypt+=encryptedNumbers[i].toString();
                    }
                    encryptField.setText(encrypt);
                    encryptList.addAll(Arrays.asList(encryptedNumbers));
                    analyzieArea.append("\n");
                }
            }
        });

        decryptBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                BigInteger[] encryptedNumbers = new BigInteger[encryptList.size()];
                encryptedNumbers = encryptList.toArray(encryptedNumbers);
                BigInteger[] decryptedNumbers = decryptMessage(encryptedNumbers, d, mod);
                analyzieArea.append("Резерв:\n");
                String decrypt="";
                for(int i=0;i<decryptedNumbers.length;i++){
                    analyzieArea.append(decryptedNumbers[i]+" ");
                }
                analyzieArea.append("\n");
                String decryptedMessage = convertNumbersToMessage(decryptedNumbers);
                analyzieArea.append(decryptedMessage);
                decryptField.setText(decryptedMessage);
            }
        });

        clearBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                privateField.setText("");
                publicField.setText("");
                pField.setText("");
                qField.setText("");
                messageField.setText("");
                analyzieArea.setText("");
                analyzieArea.setText("");
                encryptField.setText("");
                decryptField.setText("");
                phi=null;
                exp=null;
                d=null;
                mod=null;
                privateKey=null;
                publicKey=null;
                keyGenBtn.setForeground(Color.white);
            }
        });
    }

    public static void main(String[] args) {
      new RsaUi();
    }
}
