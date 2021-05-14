/**
 * Author: Wangning Shao
 * Last Modified: March 18th 2021
 *
 * This class represents a simple BlockChain.
 */
import com.google.gson.JsonObject;

import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.lang.Object;
import java.util.ArrayList;
import java.util.List;

public class BlockChain extends Object{

    //A list of BLock to imitate block chain functionality
    public List<Block> blocks;
    // chainHash will always store the last hash value
    public String chainHash;
    /**
     * default constructor for BlockChain class which initialize blocks and chainHash
     */
    public BlockChain()
    {
        blocks = new ArrayList<Block>();
        chainHash = "";
    }

    /**
     * This method will get current time
     * return current time as Timestamp
     */
    public Timestamp getTime()
    {
        return new Timestamp(System.currentTimeMillis());
    }
    /**
     * This method will get latest block
     * return latest block
     */
    public Block getLatestBlock()
    {
        return blocks.get(blocks.size()-1);
    }
    /**
     * This method will get chain size
     * return block chain size
     */
    public int getChainSize()
    {
        return blocks.size();
    }
    /**
     * This method will get difficulty
     * return # of hashes can run per second
     */
    public int hashesPerSecond() throws Exception
    {
        //start the clock
        long currentTime = System.currentTimeMillis();
        //String we will use to test our speed
        String simpleString = "00000000";
        int i = 0; //counter
        //Continue hashing until 1 second
        while (System.currentTimeMillis() - currentTime <= 1000)
        {
            // compute the digest with SHA-256
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashByte = digest.digest(simpleString.getBytes("UTF-8"));
            // Convert byte array back to String
            String hashResult = DatatypeConverter.printHexBinary(hashByte).toLowerCase();
            // Complete one hashing increment counter
            i++;
        }
        // return result
        return i;
    }
    /**
     * This method will add new block to current chain
     */
    public void addBlock(Block newBlock) throws Exception
    {
        //set up hash pointer for new block
        newBlock.setPreviousHash(chainHash);
        //calculate proof of work and assign to chianHash
        chainHash = newBlock.proofOfWork();
        // add newBlock to our chain
        blocks.add(newBlock);
    }
    /**
     * This method will check whether our chain is valid
     * return true or false
     */
    public boolean isChainValid() throws Exception {
        //set initial condition to false
        boolean isValid = false;
        //if  we only have a genesis block
        if(getChainSize() == 1)
        {
            //check block's hash value with chainHash value if they match our chain is valid
            if(blocks.get(0).calculateHash().equals(chainHash))
            {
                isValid = true;
            }
        }
        // loop through all blocks
        else
        {
            for(int i = 0; i < blocks.size(); i++)
            {
                //if it is not the last block
                if(i != (blocks.size() - 1))
                {
                    //if next block's pointer (previousHash) is the same as current block's hash
                    if(blocks.get(i+1).getPreviousHash().equals(blocks.get(i).calculateHash()))
                    {
                        isValid = true;
                    }
                    // when find a invalid block return false and break
                    else
                    {
                        isValid = false;
                        break;
                    }
                }
                //if it is last block in our chain
                else
                {
                    //check its hash value matches chainHash value
                    if(blocks.get(i).calculateHash().equals(chainHash))
                    {
                        isValid = true;
                    }
                    //if not last block is invalid
                    else
                    {
                        isValid = false;
                    }
                }
            }
        }
        return isValid;
    }
    /**
     * This method will repair our block chain by recalculate proof of work and assign to previousHash
     */
    public void repairChain() throws Exception
    {
        //loop through entire block chain
        for(int i = 0; i < blocks.size(); i++)
        {
            //if it is not the last block
            if(i != (blocks.size() - 1))
            {
                //when current block's hash doesn't match next block's previoudHash
                // we re-compute previousHash for next block
                if(!blocks.get(i+1).getPreviousHash().equals(blocks.get(i).calculateHash()))
                {
                    blocks.get(i+1).setPreviousHash(blocks.get(i).proofOfWork());
                }
            }
            //if its the last block
            else
            {
                //when last block's hash doesn't match chainHash, we recompute chainHash by calling proofOfWork
                if(!blocks.get(i).calculateHash().equals(chainHash))
                {
                    chainHash = blocks.get(i).proofOfWork();
                }
            }
        }
    }
    /**
     * This method will convert blockchain into a string
     * return json string
     */
    @Override
    public String toString()
    {
        //https://stackoverflow.com/questions/4683856/creating-gson-object
        JsonObject jsonObj = new JsonObject();
        //set key value pairs
        jsonObj.addProperty("ds_chain",blocks.toString());
        jsonObj.addProperty("chainHash",chainHash);
        //remove \s
        return jsonObj.toString().replaceAll("\\\\","");
    }

    /**
     * Below method will be used to generate last20 Byte of the
     * hash key provided
     * @param key which store information about public key
     * @return a byte array which contains last 20 byte of key
     * @throws Exception
     */
    public byte[] generateDID (String key) throws Exception {

        // compute the digest with SHA-256
        byte[] bytesOfMessage = key.getBytes("UTF-8");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] bigDigest = md.digest(bytesOfMessage);
        // create byte array to hold last 20 byte
        byte[] last20Byte = new byte[20];
        //loop through last 20 items
        for(int i = bigDigest.length-20; i < bigDigest.length;i++ )
        {
            last20Byte[i-(bigDigest.length-20)] =  bigDigest[i];
        }
        // return the last 20 byte from the key we build
        return last20Byte;
    }
}
