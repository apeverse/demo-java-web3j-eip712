import cn.hutool.core.io.IoUtil;
import cn.hutool.core.lang.Assert;
import cn.hutool.core.util.StrUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.crypto.StructuredDataEncoder;
import org.web3j.utils.Numeric;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;

public class Eip721SignatureTest {

    public static void main(String[] args) throws IOException {
        testVerifySign();
    }

    public static void testVerifySign() throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        HashMap data = objectMapper.readValue(IoUtil.readUtf8(new FileInputStream("config/did-swap.json")), HashMap.class);
        StructuredDataEncoder dataEncoder = new StructuredDataEncoder(objectMapper.writeValueAsString(data));
        byte[] bytes = dataEncoder.hashStructuredData();

        String encode = Numeric.toHexString(bytes);
        String signature = "bc21f59c4bd1fd6c4bd72bf818e2433b08f4d27adec5eff6e4bd8a7191c220456c62c37b55a38dd678194ab5b2240e686f4477066ec3d502098ffd87323d44de1b";
        // 正常情况下 这里的maker会与 config/did-swap.json 中的maker是一样的
        String marker = "0xef678007D18427E6022059Dbc264f27507CD1ffC";
        boolean b = false;
        try {
            b =verifySign(encode, marker, signature);
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
    public static   boolean verifySign(String data, String walletAddress, String signature) throws Exception {
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
}