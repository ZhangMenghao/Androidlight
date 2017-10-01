package androidlight.vpn.crypt;


import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Logger;

import javax.crypto.SecretKey;

abstract class CryptBase implements ICrypt {

    protected abstract StreamBlockCipher getCipher(boolean isEncrypted) throws InvalidAlgorithmParameterException;

    protected abstract SecretKey getKey();

    protected abstract void _encrypt(byte[] data, ByteArrayOutputStream stream);

    protected abstract void _decrypt(byte[] data, ByteArrayOutputStream stream);

    final String _name;
    private final SecretKey _key;
    final AndroidlightKey _ssKey;
    private final int _ivLength;
    private final int _keyLength;
    private boolean _encryptIVSet;
    private boolean _decryptIVSet;
    private byte[] _encryptIV;
    private byte[] _decryptIV;
    private final Lock encLock = new ReentrantLock();
    private final Lock decLock = new ReentrantLock();
    StreamBlockCipher encCipher;
    StreamBlockCipher decCipher;
    private Logger logger = Logger.getLogger(CryptBase.class.getName());

    CryptBase(String name, String password) {
        _name = name.toLowerCase();
        _ivLength = getIVLength();
        _keyLength = getKeyLength();
        _ssKey = new AndroidlightKey(password, _keyLength);
        _key = getKey();
    }

    protected void setIV(byte[] iv, boolean isEncrypt) {
        if (_ivLength == 0) {
            return;
        }

        if (isEncrypt) {
            _encryptIV = new byte[_ivLength];
            System.arraycopy(iv, 0, _encryptIV, 0, _ivLength);
            try {
                encCipher = getCipher(isEncrypt);
                ParametersWithIV parameterIV = new ParametersWithIV(new KeyParameter(_key.getEncoded()), _encryptIV);
                encCipher.init(isEncrypt, parameterIV);
            } catch (InvalidAlgorithmParameterException e) {
                logger.info(e.toString());
            }
        } else {
            _decryptIV = new byte[_ivLength];
            System.arraycopy(iv, 0, _decryptIV, 0, _ivLength);
            try {
                decCipher = getCipher(isEncrypt);
                ParametersWithIV parameterIV = new ParametersWithIV(new KeyParameter(_key.getEncoded()), _decryptIV);
                decCipher.init(isEncrypt, parameterIV);
            } catch (InvalidAlgorithmParameterException e) {
                logger.info(e.toString());
            }
        }
    }

    @Override
    public byte[] encrypt(byte[] data) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        encrypt(data, stream);
        return stream.toByteArray();
    }

    @Override
    public void encrypt(byte[] data, ByteArrayOutputStream stream) {
        synchronized (encLock) {
            stream.reset();
            if (!_encryptIVSet) {
                _encryptIVSet = true;
                byte[] iv = new byte[_ivLength];
                new SecureRandom().nextBytes(iv);
                setIV(iv, true);
                try {
                    stream.write(iv);
                } catch (IOException e) {
                    logger.info(e.toString());
                }

            }

            _encrypt(data, stream);
        }
    }

    @Override
    public void encrypt(byte[] data, int length, ByteArrayOutputStream stream) {
        byte[] d = new byte[length];
        System.arraycopy(data, 0, d, 0, length);
        encrypt(d, stream);
    }

    @Override
    public byte[] decrypt(byte[] cipher) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        decrypt(cipher, stream);
        return stream.toByteArray();
    }

    @Override
    public void decrypt(byte[] cipher, ByteArrayOutputStream stream) {
        byte[] temp;

        synchronized (decLock) {
            stream.reset();
            if (!_decryptIVSet) {
                _decryptIVSet = true;
                setIV(cipher, false);
                temp = new byte[cipher.length - _ivLength];
                System.arraycopy(cipher, _ivLength, temp, 0, cipher.length - _ivLength);
            } else {
                temp = cipher;
            }

            _decrypt(temp, stream);
        }
    }

    @Override
    public void decrypt(byte[] cipher, int length, ByteArrayOutputStream stream) {
        byte[] d = new byte[length];
        System.arraycopy(cipher, 0, d, 0, length);
        decrypt(d, stream);
    }
}
