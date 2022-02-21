// Java program for Client
import java.io.*;
import java.net.*;
import java.util.Date;
import java.util.List;
import java.util.Base64;
import java.util.Calendar;
import java.util.ArrayList;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.BadPaddingException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;

class Message implements Serializable {
	private String recipient;
	private String sender;
	private Date timestamp;
	private String message;
	private boolean isEncrypted;
	private byte[] signature;

	public Message(String recipient, String sender, Date timestamp, String message, boolean isEncrypted, byte[] signature) {
		this.recipient = recipient;
		this.sender = sender;
		this.timestamp = timestamp;
		this.message = message;
		this.isEncrypted = isEncrypted;
		this.signature = signature;
	}

	public String getRecipient() {
		return recipient;
	}

	public String getSender() {
		return sender;
	}

	public Date getTimestamp() {
		return timestamp;
	}

	public String getMessage() {
		return message;
	}

	public boolean isEncrypted() {
		return isEncrypted;
	}

	public byte[] getSignature() {
		return signature;
	}
}

public class Client {
	// initialize socket and input output streams
	private static Socket socket = null;

	// constructor to put ip address and port
	public Client(String address, int port) {
		// establish a connection
		try {
			socket = new Socket(address, port);
		}
		catch(ConnectException c)
		{
			System.out.println("Connection refused. You need to initiate a server first.");
			// System.out.println(c);
		}
		catch(UnknownHostException u)
		{
			System.out.println(u);
		}
		catch(IOException i)
		{
			System.out.println(i);
		}
	}

	// Function to encrypt the message
	private static String encrypt(String message, String publicKeyFileName) {
		try {
			// Read the public key from file
			FileInputStream publicKeyFile = new FileInputStream("../RSAKeyGen/" + publicKeyFileName + ".pub");
			ObjectInputStream in = new ObjectInputStream(publicKeyFile);
			PublicKey publicKey = (PublicKey) in.readObject();
			in.close();

			// Encrypt message using public key
			Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] encryptedMessageBytes = encryptCipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
			// Encodes the byte array into a base64 string
			String encodedMessage = Base64.getEncoder().encodeToString(encryptedMessageBytes);
			return encodedMessage;
		} catch (FileNotFoundException e) {
			System.out.println(publicKeyFileName + ".pub file not found.");
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} 

		// If encryption fails for some reason, return the original message
		return message;
	}

	// Function to decrypt the message
	private static String decrypt(String message, String privateKeyFileName) {
		try {
			// Read the private key from file
			FileInputStream privateKeyFile = new FileInputStream("../RSAKeyGen/" + privateKeyFileName + ".prv");
			ObjectInputStream in = new ObjectInputStream(privateKeyFile);
			PrivateKey privateKey = (PrivateKey) in.readObject();
			in.close();
		
			// Decrypt message using private key
			Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] encryptedMessageBytes = Base64.getDecoder().decode(message);
			byte[] decryptedMessageBytes = decryptCipher.doFinal(encryptedMessageBytes);
			String decodedMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);
			return decodedMessage;
		} catch (FileNotFoundException e) {
			System.out.println(privateKeyFileName + ".prv file not found.");
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (IllegalArgumentException e) {
			return message;
		} catch (BadPaddingException e) {
			return message;
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
		return message;
	}

	// Function to sign the message
	public static byte[] sign(String message, String privateKeyFileName) {
		try {
			// Create signature
			// Read the private key from file
			FileInputStream privateKeyFile = new FileInputStream("../RSAKeyGen/" + privateKeyFileName + ".prv");
			ObjectInputStream in = new ObjectInputStream(privateKeyFile);
			PrivateKey privateKey = (PrivateKey) in.readObject();
			in.close();

			// create signature
			Signature signatureObject = Signature.getInstance("SHA1withRSA");
			signatureObject.initSign(privateKey);
			signatureObject.update(message.getBytes());
			byte[] signature = signatureObject.sign();
			return signature;
		} catch (FileNotFoundException e) {
			System.out.println(privateKeyFileName + ".prv file not found.");
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static Message makeMessage(String sender) {
		try {
			// Ask user if they want to send a message
			System.out.println("Do you want to add a post? [y/n]");
			BufferedReader inFromUser = new BufferedReader(new InputStreamReader(System.in));
			String answer = inFromUser.readLine();

			OutputStream outputStream = socket.getOutputStream();
			ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
			// If they want to send a message
			if (answer.toLowerCase().equals("y")) {
				// Inform the server that the client wants to send a message
				objectOutputStream.writeObject(true);
		
				// Read recipient name from terminal
				System.out.println("\nEnter the recipient userid (type \"all\" for posting without encryption): ");
				String recipient = new BufferedReader(new InputStreamReader(System.in)).readLine();

				// Read message from terminal
				System.out.println("\nEnter your message: ");
				String message = new BufferedReader(new InputStreamReader(System.in)).readLine();
			
				boolean isEncrypted = false;
				// If the recipient is not "all", then encrypt the message
				if (!recipient.toLowerCase().equals("all")) {
					message = encrypt(message, recipient);
					isEncrypted = true;
				}
				Date timestamp = Calendar.getInstance().getTime();
				// Sign the message
				byte[] signature = sign((sender + message + timestamp), sender);
				return new Message(recipient, sender, timestamp, message, isEncrypted, signature);
			}
			// If user don't want to send a message
			else {
				// Inform the server that the client doesn't want to send a message
				objectOutputStream.writeObject(false);
				return null;
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}

	// Function to send message to server
	public static void sendMessage(Message message) throws IOException {
		// Send message to the socket
		OutputStream outputStream = socket.getOutputStream();
        // Create an object output stream from the output stream so we can send an object through it
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
		objectOutputStream.writeObject(message);
		return;
	}

	public static void main(String args[]) {
        String host = args[0];
        String port = args[1];
        String sender = args[2];
        new Client(host, Integer.parseInt(port));

		// Check if socket is connected
		if (socket != null) {
			try {
				// Create input and output streams
				InputStream inputStream = socket.getInputStream();
				ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);

				// Read messages from the server
				List<Message> messages = (List<Message>) objectInputStream.readObject();

				// Print total message count
				System.out.println("There are " + messages.size() + " post(s).\n");
				// If there are messages, print them
				for (Message message : messages) {
					System.out.println("Sender: " + message.getSender());
					System.out.println("Timestamp: " + message.getTimestamp());
					// If the message is encrypted, decrypt it
					if (message.isEncrypted()) {
						System.out.println("Message: " + decrypt(message.getMessage(), sender));
					}
					else {
						System.out.println("Message: " + message.getMessage());
					}
					System.out.println();
				}

				// Read message from terminal
				Message message = makeMessage(sender);

				// Send message to the socket
				if (message != null) {
					sendMessage(message);
				}

				// Close the socket
				socket.close();
			} catch (IOException e) {
				e.printStackTrace();
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			}
		}
	}
}
