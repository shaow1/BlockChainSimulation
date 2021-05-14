/**
 * Author: Wangning Shao
 * Last Modified: March 20th 2021
 *
 * This program demonstrates a very simple TCP server with RSA Signature verification.
 * When the server get the requested it will verify user's identity then perform operation
 * user requested
 * and send the result back to client
 */
import com.google.gson.JsonObject;
import org.json.JSONObject;
import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.net.*;
import java.io.*;
import java.security.MessageDigest;
import java.util.Map;
import java.util.Scanner;
import java.util.TreeMap;

public class VerifyingServerTCP {

    public static Map<String, String> users = new TreeMap<>();
    /**
     * No command line arguments needed.
     */
    public static void main(String args[]) {
        // define a TCP style socket
        Socket clientSocket = null;
        try {
            // the server port we are using
            int serverPort = 7777;
            // Create a new server socket
            ServerSocket listenSocket = new ServerSocket(serverPort);

            //Create a BlockChain instance so we can access method inside
            BlockChain bc = new BlockChain();
            //Add genesis block
            bc.addBlock(new Block(0, bc.getTime(), "Genesis", 2));

            /*
             * Forever,
             *   read a line from the socket
             *   print it to the console
             *   echo it (i.e. write it) back to the client
             */
            while (true) {
                /*
                 * Block waiting for a new connection request from a client.
                 * When the request is received, "accept" it, and the rest
                 * the tcp protocol handshake will then take place, making
                 * the socket ready for reading and writing.
                 */
                // Connect to a client.
                clientSocket = listenSocket.accept();

                // Set up "in" to read from the client socket
                Scanner in;
                in = new Scanner(clientSocket.getInputStream());

                // Set up "out" to write to the client socket
                PrintWriter out;
                out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream())));
                // read data coming from client side
                String command = in.nextLine();
                //precheck public key hash to the ID and signature matches
                if(!(checkID(command) && checkSign(command)))
                {
                    //if failed send "Error in request!"
                    JsonObject jsonObj = new JsonObject();
                    jsonObj.addProperty("error","Error in request!");
                    out.println(jsonObj.toString());
                    out.flush();
                }
                //otherwise proceed to perform user required operation
                else
                {
                    JSONObject jsonObject = new JSONObject(command); // create a new JSONObject
                    //accessing the operation user provided by "operation" key
                    String operation = jsonObject.getString("operation");
                    //this JsonObject will hold result after each operation
                    JsonObject jsonObj = new JsonObject();
                    //Check if the operation is view
                    if(operation.equals("0"))
                    {
                        //call view method
                        jsonObj = view(bc);
                    }
                    else if(operation.equals("1"))
                    {
                        //get parameters need for addBlock method which is provided by user
                        String rsa = jsonObject.getString("rsa");
                        int diff = jsonObject.getInt("difficulty");
                        //call addBlock method
                        jsonObj = addBlock(bc, rsa, diff);
                    }
                    //Check if the operation is subtraction
                    else if(operation.equals("2"))
                    {
                        //call isValid method
                        jsonObj = isValid(bc);
                    }
                    //Check if the operation is view
                    else if(operation.equals("3"))
                    {
                        //call toString method
                        jsonObj = toString(bc);
                    }
                    //Check if the operation is view
                    else if(operation.equals("4"))
                    {
                        //get parameters need for corrupt method which is provided by user
                        String newData = jsonObject.getString("value");
                        int index = jsonObject.getInt("index");
                        //call corrupt method
                        jsonObj = corrupt(bc, newData, index);
                    }
                    //Check if the operation is view
                    else if(operation.equals("5"))
                    {
                        //call repair method
                        jsonObj = repair(bc);
                    }
                    //send result back to client
                    out.println(jsonObj.toString());
                    out.flush();
                }
            }

            // Handle IOExceptions
        } catch (IOException e) {
            System.out.println("IO Exception:" + e.getMessage());

            // If quitting (typically by you sending quit signal) clean up sockets
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (clientSocket != null) {
                    clientSocket.close();
                }
            } catch (IOException e) {
                // ignore exception on close
            }
        }
    }
    /**
     * @param bc, current Blockchain
     * return the jsonObj
     */
    public static JsonObject repair(BlockChain bc) throws Exception {
        JsonObject jsonObj = new JsonObject(); //create a JsonObject will hold return result
        //start the clock
        long startRepair = System.currentTimeMillis();
        // call repairChain() to repair corrupted blocks if any
        bc.repairChain();
        //stop the clock
        long finishRepairing = System.currentTimeMillis();
        // calculate the time
        int totalTime = (int) (finishRepairing - startRepair);
        //add operation time to JsonObject that we created
        jsonObj.addProperty("totalTime", totalTime);
        return jsonObj;
    }


    /**
     * @param bc, current Blockchain
     * return the jsonObj
     */
    public static JsonObject addBlock(BlockChain bc, String rsa, int diff) throws Exception {
        JsonObject jsonObj = new JsonObject(); //create a JsonObject will hold return result
        //Convert last 20 byte of client's public key into string
        String did = DatatypeConverter.printHexBinary(bc.generateDID(rsa)).toLowerCase();
        jsonObj.addProperty("did", did);
        String data = rsa + "," + did; //Construct public key with DID as data
        jsonObj.addProperty("data", data);

        long start = System.currentTimeMillis(); // get current time
        //add user specified block into chain
        bc.addBlock(new Block(bc.getLatestBlock().getIndex() + 1, bc.getTime(), data, diff));
        //end clock
        long end = System.currentTimeMillis();
        //calculate the time
        int totalAddTime = (int) (end - start);
        //add operation time to JsonObject that we created
        jsonObj.addProperty("totalTime", totalAddTime);
        return jsonObj;
    }
    /**
     * @param bc, current Blockchain
     * return the jsonObj
     */
    public static JsonObject corrupt(BlockChain bc, String data, int index) throws Exception {
        JsonObject jsonObj = new JsonObject(); //create a JsonObject will hold return result
        bc.blocks.get(index).setData(data); // modify corresponding block
        //add new data that we get from corresponding block to JsonObject that we created
        jsonObj.addProperty("newData", bc.blocks.get(index).getData());
        return jsonObj;
    }
    /**
     * @param bc, current Blockchain
     * return the jsonObj
     */
    public static JsonObject toString(BlockChain bc) throws Exception {
        JsonObject jsonObj = new JsonObject(); //create a JsonObject will hold return result
        //add string value of entire chain to JsonObject that we created
        jsonObj.addProperty("blockchain",bc.toString());
        return jsonObj;
    }
    /**
     * @param bc, current Blockchain
     * return the jsonObj
     */
    public static JsonObject view(BlockChain bc) throws Exception {
        JsonObject jsonObj = new JsonObject(); //create a JsonObject will hold return result
        jsonObj.addProperty("chainSize",bc.getChainSize()); //add chainSize to JsonObject that we created
        jsonObj.addProperty("hashPerSecond",bc.hashesPerSecond()); //add hashPerSecond to JsonObject that we created
        jsonObj.addProperty("difficulty",bc.getLatestBlock().getDifficulty()); //add difficulty to JsonObject that we created
        jsonObj.addProperty("nonce",bc.getLatestBlock().getNonce()); //add nonce to JsonObject that we created
        jsonObj.addProperty("chainHash",bc.chainHash); //add chainHash to JsonObject that we created
        return jsonObj;
    }
    /**
     * @param bc, current Blockchain
     * return the jsonObj
     */
    public static JsonObject isValid(BlockChain bc) throws Exception {
        // start the clock
        long currentTime = System.currentTimeMillis();
        //call isChinaValid method to validate current chain
        boolean result = bc.isChainValid();
        // end clock
        long endTime = System.currentTimeMillis();
        // calculate the time
        int totalTime = (int) (endTime - currentTime);

        JsonObject jsonObj = new JsonObject(); //create a JsonObject will hold return result
        if(result == true)
        {
            //if chain is valid we add TRUE to JsonObject that we created
            jsonObj.addProperty("result", Boolean.TRUE);
        }
        else
        {
            //else we add FALSE to JsonObject that we created
            jsonObj.addProperty("result", Boolean.FALSE);
        }
        //add operation time to JsonObject that we created
        jsonObj.addProperty("totalTime",totalTime);
        return jsonObj;
    }

    public static boolean checkSign(String message)throws Exception
    {
        JSONObject jsonObject = new JSONObject(message); //create a JSONObject which contains the message value
        //Split n and e using ; we inserted
        String[] keys = jsonObject.getString("keyComb").split(";");
        //Assign corresponding values to e and n
        BigInteger e = new BigInteger(keys[0]);
        BigInteger n = new BigInteger(keys[1]);
        //get user ID by finding the key "id" in JSONObject that we created
        String id = jsonObject.getString("id");
        //get user provided value by finding the key "value" in JSONObject that we created
        String value = jsonObject.getString("value");
        //get user provided operation by finding the key "operation" in JSONObject that we created
        String operation = jsonObject.getString("operation");

        // Take the encrypted string and make it a big integer
        BigInteger encryptedHash = new BigInteger(jsonObject.getString("signedVal"));

        // Decrypt it
        BigInteger decryptedHash = encryptedHash.modPow(e, n);

        //Create a message which will be used to check user's signature
        String messageToCheck = String.valueOf(id) + e + ";" + n + value + operation;

        // Get the bytes from messageToCheck
        byte[] bytesOfMessageToCheck = messageToCheck.getBytes("UTF-8");

        // compute the digest of the message with SHA-256
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] messageToCheckDigest = md.digest(bytesOfMessageToCheck);

        // messageToCheckDigest is a full SHA-256 digest
        // take two bytes from SHA-256 and add a zero byte
        byte[] extraByte = new byte[messageToCheckDigest.length + 1];
        extraByte[0] = 0;
        for(int i = 1; i < messageToCheckDigest.length; i++)
        {
            extraByte[i] = messageToCheckDigest[i-1];
        }

        // Make it a big int
        BigInteger bigIntegerToCheck = new BigInteger(extraByte);

        // inform the client on how the two compare
        // if message we generate match the one is signed
        // the message is send from trust client
        if(bigIntegerToCheck.compareTo(decryptedHash) == 0)
        {
            return true;
        }
        else {
            return false;
        }
    }


    public static boolean checkID(String message)throws Exception {
        JSONObject jsonObject = new JSONObject(message); //create a JSONObject which contains the message value
        //Split n and e using ; we inserted
        String[] keys = jsonObject.getString("keyComb").split(";");
        //Assign corresponding values to e and n
        BigInteger e = new BigInteger(keys[0]);
        BigInteger n = new BigInteger(keys[1]);

        //get user ID by finding the key "id" in JSONObject that we created
        String id = jsonObject.getString("id");

        //generate composite keys with e and n
        String input = e.toString() + n.toString();
        // compute the digest with SHA-256
        byte[] bytesOfMessage = input.getBytes("UTF-8");
        MessageDigest md1 = MessageDigest.getInstance("SHA-256");
        byte[] bigDigest = md1.digest(bytesOfMessage);
        // create byte array to hold last 20 byte
        byte[] last20Byte = new byte[20];
        //loop through last 20 items
        for (int i = bigDigest.length - 20; i < bigDigest.length; i++) {
            last20Byte[i - (bigDigest.length - 20)] = bigDigest[i];
        }
        //Convert byte array into string
        String checkID = DatatypeConverter.printHexBinary(last20Byte).toLowerCase();
        //Check whether id we received from message and the one we compute are the same
        if (!checkID.equals(id)) {
            return false;
        } else {
            return true;
        }
    }
}
