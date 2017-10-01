package androidlight.vpn.crypt;

import java.io.ByteArrayOutputStream;

public interface ICrypt {
    byte[] encrypt(byte[] data);
    void encrypt(byte[] data, ByteArrayOutputStream stream);
    void encrypt(byte[] data, int length, ByteArrayOutputStream stream);

    byte[] decrypt(byte[] cipher);
    void decrypt(byte[] cipher, ByteArrayOutputStream stream);
    void decrypt(byte[] cipher, int length, ByteArrayOutputStream stream);

    int getIVLength();
    int getKeyLength();
}
