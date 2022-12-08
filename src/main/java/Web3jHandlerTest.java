
import cn.hutool.core.io.IoUtil;
import cn.hutool.core.lang.Assert;
import cn.hutool.core.util.StrUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.web3j.crypto.*;
import org.web3j.utils.Numeric;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;

public class Web3jHandlerTest {

    public static void main(String[] args) throws IOException {
        testVerifyWithNest();
    }

    /**
     * 嵌套结构验签
     * @throws IOException
     */
    public static void testVerifyWithNest() throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        HashMap data = objectMapper.readValue(IoUtil.readUtf8(new FileInputStream("config/test_nest.json")), HashMap.class);
        StructuredDataEncoder dataEncoder = new StructuredDataEncoder(objectMapper.writeValueAsString(data));
        byte[] bytes = dataEncoder.hashStructuredData();
        String encode = Numeric.toHexString(bytes);
        System.out.println(encode);
//        EIP712Handler eip712Handler = new EIP712Handler();
        // 这里是签名
//        String signature = eip712Handler.sign(encode,"e140128d03a44d24905a65ef03d9d8435fcc2b7f636c6e26c966ea3ed1aed59e");
//        System.out.println(signature);
        String signature = "8aaf12894150b785e69f4e130dbc51705dc0b61714c8362c17f1d31904bb898a2d37e77fa437e3df3dc8195befcf0e602f68f3fb88bc738e51da7de7a4f83f2d1c";
        String marker = "0xf746f437b3e4ede14105b2ade0eab9a937ebde5d";
        boolean b = false;
        try {
            b = verifySign(encode, marker, signature);
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assert.isTrue(b);
    }


    public static void testVerifySign() throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        HashMap data = objectMapper.readValue(IoUtil.readUtf8(new FileInputStream("config/test.json")), HashMap.class);
        StructuredDataEncoder dataEncoder = new StructuredDataEncoder(objectMapper.writeValueAsString(data));
        byte[] bytes = dataEncoder.hashStructuredData();

        String encode = Numeric.toHexString(bytes);
        String signature = "34a5e77ee3fad2cd8f69024851f1350bb3727f44037b11287b5a44fd1915715e53ca8b0babbddbf59c75ce0d6de5c64b60b85b0f404ff3dd8f22f67dd72d5a771c";
        String marker = "0x12eEe4aEE6a08aE21663D7BF23b0BCecdE30C5D4";
        boolean b = false;
        try {
            b = verifySign(encode, marker, signature);
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assert.isTrue(b);
    }

    /**
     * verify data
     * get public key and get wallet address with sign
     *
     * @param data          签名数据，encode之后的哈希
     * @param walletAddress 签名的钱包地址
     * @param signature     签名数据（r,s,v）
     * @return boolean
     * @throws Exception e
     */
    public static boolean verifySign(String data, String walletAddress, String signature) throws Exception {
        try {
            if (StrUtil.isBlank(data)) {
                return false;
            }

            byte[] signatureBytes = Numeric.hexStringToByteArray(signature);
            byte[] r = Arrays.copyOfRange(signatureBytes, 0, 32);
            byte[] s = Arrays.copyOfRange(signatureBytes, 32, 64);
//            byte v = signatureBytes[64];
            int recId = signatureBytes[64];
            if (recId >= 27) {
                recId = recId - 27;
            }

            ECDSASignature sig = new ECDSASignature(new BigInteger(1, r), new BigInteger(1, s));
            byte[] hashMsg = Numeric.hexStringToByteArray(data);
            BigInteger recoverPubKey = Sign.recoverFromSignature(recId, sig, hashMsg);
            return StrUtil.equalsIgnoreCase("0x" + Keys.getAddress(recoverPubKey), walletAddress);
        } catch (Exception e) {
            e.printStackTrace();
            throw new Exception(e);
        }
    }

    /*
     * sign data
     * sign with private key and return rsv
     *
     * @param hashStructuredData   签名数据，原始数据
     * @param privateKey 私钥
     * @return String rsv
     */
    public String sign(String hashStructuredData, String privateKey) {
        // 1. 创建公私钥对
        Credentials credentials = Credentials.create(privateKey);
        // 2. 准备要签名的数据
        byte[] hashMsg = Numeric.hexStringToByteArray(hashStructuredData);
        // 3. 对数据进行签名
        Sign.SignatureData signature = Sign.signMessage(hashMsg, credentials.getEcKeyPair(), false);

        // 3.1. 签名转字符串
        byte[] sig_data = ByteBuffer.allocate(signature.getR().length + signature.getS().length + signature.getV().length)
                .put(signature.getR())
                .put(signature.getS())
                .put(signature.getV())
                .array();
        return Numeric.toHexStringNoPrefix(sig_data);
    }
}