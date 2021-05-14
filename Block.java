/**
 * Author: Wangning Shao
 * Last Modified: March 18th 2021
 *
 * This class represents a simple Block.
 * Each Block object has an index, a timestamp, a field named data, a previousHash and a nonce.
 * This class contains getter and setter for above values and a calculateHash method
 * a proofOfWork method and override Object's toString method
 */
import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.lang.Object;
import com.google.gson.JsonObject;

public class Block extends Object{
    private int index; //the position of the block on the chain. The first block (the so called Genesis block) has an index of 0.
    private Timestamp timestamp; //a Java Timestamp object, it holds the time of the block's creation.
    private String data; // a String holding the block's single transaction details.
    private String previousHash; // the SHA256 hash of a block's parent. This is also called a hash pointer.
    private BigInteger nonce; //a BigInteger value determined by a proof of work routine
    private int difficulty; // it is an int that specifies the exact number of left most hex digits needed by a proper hash.
    /**
     * This is the constructor which set values for index, timestamp, data and difficulty
     */
    public Block(int index, Timestamp timestamp, String data, int difficulty)
    {
        setIndex(index); //Call setIndex method to initialize index
        setTimestamp(timestamp); //Call setTimestamp method to initialize timestamp
        setData(data); //Call setData method to initialize data
        setDifficulty(difficulty); //Call setDifficulty method to initialize difficulty
    }
    /**
     * This method computes a hash of the concatenation of the index, timestamp, data, previousHash, nonce, and difficulty.
     * return a String holding Hexadecimal characters
     */
    public String calculateHash() throws Exception
    {
        //Get index,timestamp, data, previousHash, nonce and difficulty using getters
        int index = getIndex();
        Timestamp ts = getTimestamp();
        String data = getData();
        String previousHash = getPreviousHash();
        BigInteger nonce = getNonce();
        int difficulty = getDifficulty();
        //Construct above values into a String and prepare for hashing
        String hash = index + "," + ts.toString() + ","  + data + ","  + previousHash + ","  + nonce.toString() + ","  + difficulty;
        // compute the digest with SHA-256
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashByte = digest.digest(hash.getBytes("UTF-8"));
        // Convert byte array back to String
        String hashResult = DatatypeConverter.printHexBinary(hashByte).toLowerCase();
        // return hashing results
        return hashResult;
    }
    /**
     * This method returns the nonce for this block. The nonce is a number that has been found to cause the hash
     * of this block to have the correct number of leading hexadecimal zeroes.
     * return a BigInteger representing the nonce for this block.
     */
    public BigInteger getNonce()
    {
        return nonce;
    }
    /**
     * This method calls calculateHash() to compute a hash of the concatenation of the index, timestamp, data,
     * previousHash, nonce, and difficulty. If the hash has the appropriate number of leading hex zeroes,
     * it is done and returns that proper hash. If the hash does not have the appropriate number of leading hex zeroes,
     * it increments the nonce by 1 and tries again. It continues this process, burning electricity and CPU cycles,
     * until it gets lucky and finds a good hash.
     * return a String with a hash that has the appropriate number of leading hex zeroes.
     */
    public String proofOfWork() throws Exception
    {
        //set nonce to 0
        nonce = BigInteger.ZERO;
        //continue process until find a good hash
        while(true)
        {
            //calculate hash
            String hash = calculateHash();
            //get leading zeros based on difficulty
            String leadingZeros = hash.substring(0,difficulty);
            //generate 0s which match difficulty
            String difficultyZeros = String.format("%0"+difficulty+"d",0);
            //Compare 0s with difficulty if match then it will be a good hash we return hash
            //else increment nonce by 1 repeat
            if(leadingZeros.equals(difficultyZeros))
            {
                return hash;
            }
            else
            {
                nonce = nonce.add(BigInteger.ONE);
            }
        }
    }
    /**
     * This method will get difficulty
     * return difficulty
     */
    public int getDifficulty()
    {
        return difficulty;
    }
    /**
     * This method will set difficulty
     * @params difficulty - determines how much work is required to produce a proper hash
     */
    public void setDifficulty(int difficulty)
    {
        this.difficulty = difficulty;
    }
    /**
     * This method Overrides toString in class java.lang.Object
     * return a A JSON representation of all of this block's data is returned.
     */
    @Override
    public String toString()
    {
        //https://stackoverflow.com/questions/4683856/creating-gson-object
        JsonObject jsonObj = new JsonObject();
        jsonObj.addProperty("index",getIndex());
        jsonObj.addProperty("time stamp",getTimestamp().toString());
        jsonObj.addProperty("Tx",getData());
        jsonObj.addProperty("PrevHash",getPreviousHash());
        jsonObj.addProperty("nonce",getNonce());
        jsonObj.addProperty("difficulty",getDifficulty());
        return jsonObj.toString();
    }
    /**
     * This method will set previousHash
     * @params previousHash - a hash pointer to this block's parent
     */
    public void setPreviousHash(String previousHash)
    {
        this.previousHash = previousHash;
    }
    /**
     * This method will get previousHash
     * return previousHash
     */
    public String getPreviousHash()
    {
        return previousHash;
    }
    /**
     * This method will get current Index
     * return an integer index
     */
    public int getIndex()
    {
        return index;
    }
    /**
     * This method will set index
     * @params index - the index of this block in the chain
     */
    public void setIndex(int index)
    {
        this.index = index;
    }
    /**
     * This method will set timestamp
     * @params timestamp - of when this block was created
     */
    public void setTimestamp(Timestamp timestamp)
    {
        this.timestamp = timestamp;
    }
    /**
     * This method get current timestamp
     * return a timestamp of this block
     */
    public Timestamp getTimestamp()
    {
        return timestamp;
    }
    /**
     * This method will get data for current transaction
     * return this block's transaction
     */
    public String getData()
    {
        return  data;
    }
    /**
     * This method will set data
     * @params data - represents the transaction held by this block
     */
    public void setData(String data)
    {
        this.data = data;
    }
}