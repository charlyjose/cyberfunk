// Java program for Server
import java.net.*;
import java.io.*;
import java.util.Date;
import java.util.List;
import java.security.*;
import java.util.ArrayList;

class Message implements Serializable {
	private String recipient;
	private String sender;
	private Date timestamp;
	private String message;
	private byte[] signature;

	public Message(String recipient, String sender, Date timestamp, String message, byte[] signature) {
		this.recipient = recipient;
		this.sender = sender;
		this.timestamp = timestamp;
		this.message = message;
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

	public byte[] getSignature() {
		return signature;
	}
}

public class Server {
	// Initialize socket and messages array
    private static ServerSocket serverSocket = null;
    private static List<Message> messages = new ArrayList<>();

	// Constructor with port
	public Server(int port) {
        try {
            serverSocket = new ServerSocket(port);
        }
        catch(IOException i)
        {
            System.out.println(i);
        }
	}

    // Function to verify signature
    public static boolean verifySignature(Message message) {
        try {
            // read public key to verify signature
            FileInputStream publicKeyFile = new FileInputStream(message.getSender() + ".pub");
            ObjectInputStream in = new ObjectInputStream(publicKeyFile);
            PublicKey publicKey = (PublicKey) in.readObject();
            in.close();

            // Recreate signature
            Signature signatureObject = Signature.getInstance("SHA1withRSA");
            
            // verify signature
            signatureObject.initVerify(publicKey);
            signatureObject.update((message.getSender() + message.getMessage() + message.getTimestamp()).getBytes());
            boolean verified = signatureObject.verify(message.getSignature());
            if (verified) return true;
            else return false;
        } catch (FileNotFoundException e) {
			System.out.println(message.getSender() + ".pub file not found.");
        } catch(Exception e) {
            System.out.println(e);
        }

        return false;
    }

    // Function to handle client requests
    public static void readMessages(Socket socket) {
        // If client is connected and server is listening
        while(!socket.isClosed() && socket.isConnected()) {
            try {
                // Get the input stream from the connected socket
                InputStream inputStream = socket.getInputStream();
                // Create a DataInputStream so we can read data from it.
                ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);

                // Read the message sent by the client
                Message message = (Message) objectInputStream.readObject();

                // Print the message object
                System.out.println("Sender: " + message.getSender());
                System.out.println("Timestamp: " + message.getTimestamp());
                System.out.println("Message: " + message.getMessage());

                // Verify the signature
                if(verifySignature(message)) {
                    System.out.println("Signature verified");
                    // Add the message to the list of messages
                    messages.add(message);
                }
                else {
                    System.out.println("Signature not verified. Discarding message.");
                }

                // close the socket
                socket.close();
            } catch (IOException e) {
                // System.out.println("Connection closed");
                // System.out.println(e.getMessage());
                e.printStackTrace();
                break;
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
                break;
            }
        }
        return;
    }

    // Function to send messages to client
	public static void sendMessages(ObjectOutputStream objectOutputStream, List<Message> messages) {
        try{
            // Send the list of messages to the client
            objectOutputStream.writeObject(messages);
            return;
        }  catch (IOException e) {
            System.out.println(e);
        }
	}

    // Function to connect to the client
    private static void connectClient(ServerSocket serverSocket) {
        // Wait for a new client to connect
        while(true) {
            try {
                Socket socket = serverSocket.accept();
                // Create an output stream from the socket
                OutputStream outputStream = socket.getOutputStream();
                ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
                // Send all messages to the client
                sendMessages(objectOutputStream, messages);

                // Check if the client wants to send a message
                // Get the input stream from the connected socket
                InputStream inputStream = socket.getInputStream();
                // Create a DataInputStream so we can read data from it.
                ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
                Boolean newMessageBoolean = (Boolean) objectInputStream.readObject();
                if(newMessageBoolean) {
                    // Read the message sent by the client
                    readMessages(socket);
                }
                else {
                    // Close the socket
                    // System.out.println("Client not sending messages");
                    socket.close();
                }
            } catch (IOException | ClassNotFoundException e) {
                System.out.println(e.getMessage());
            }
        }
    }

    // Main function
	public static void main(String args[]) throws IOException {
        try {
        String port = args[0];
        // create a Server object
        new Server(Integer.parseInt(port));
        // Client Connecter
        connectClient(serverSocket);
        } catch (ArrayIndexOutOfBoundsException e) {
            System.out.println("Please enter a port number");
        } catch (NumberFormatException e) {
            System.out.println("Please enter a valid port number");
        } catch (Exception e) {
            System.out.println(e);
        } finally {
            serverSocket.close();
        }
	}
}
