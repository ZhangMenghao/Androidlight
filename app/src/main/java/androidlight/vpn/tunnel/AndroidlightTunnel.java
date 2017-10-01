package androidlight.vpn.tunnel;


import java.nio.ByteBuffer;
import java.nio.channels.Selector;

import androidlight.vpn.config.AndroidlightConfig;
import androidlight.vpn.crypt.CryptFactory;
import androidlight.vpn.crypt.ICrypt;

//AndroidlightTunnel加密隧道
public class AndroidlightTunnel extends Tunnel {

    private ICrypt m_Encryptor;
    private AndroidlightConfig m_Config;
    private boolean m_TunnelEstablished;

    public AndroidlightTunnel(AndroidlightConfig config, Selector selector) throws Exception {
        super(config.ServerAddress, selector);
        m_Config = config;
        m_Encryptor = CryptFactory.get(m_Config.EncryptMethod, m_Config.Password);

    }

    @Override
    protected void onConnected(ByteBuffer buffer) throws Exception {

        buffer.clear();

        buffer.put((byte) 0x03);//domain
        byte[] domainBytes = m_DestAddress.getHostName().getBytes();
        buffer.put((byte) domainBytes.length);//domain length;
        buffer.put(domainBytes);
        buffer.putShort((short) m_DestAddress.getPort());
        buffer.flip();
        byte[] _header = new byte[buffer.limit()];
        buffer.get(_header);

        buffer.clear();
        buffer.put(m_Encryptor.encrypt(_header));
        buffer.flip();

        if (write(buffer, true)) {
            m_TunnelEstablished = true;
            onTunnelEstablished();
        }
        else {
            m_TunnelEstablished = true;
            this.beginReceive();
        }
    }

    @Override
    protected boolean isTunnelEstablished() {
        return m_TunnelEstablished;
    }

    //发送数据之前加密
    @Override
    protected void beforeSend(ByteBuffer buffer) throws Exception {

        byte[] bytes = new byte[buffer.limit()];
        buffer.get(bytes);

        byte[] newbytes = m_Encryptor.encrypt(bytes);

        buffer.clear();
        buffer.put(newbytes);
        buffer.flip();
    }

    //接收数据之后解密
    @Override
    protected void afterReceived(ByteBuffer buffer) throws Exception {
        byte[] bytes = new byte[buffer.limit()];
        buffer.get(bytes);
        byte[] newbytes = m_Encryptor.decrypt(bytes);
        String s = new String(newbytes);
        buffer.clear();
        buffer.put(newbytes);
        buffer.flip();
    }

    @Override
    protected void onDispose() {
        m_Config = null;
        m_Encryptor = null;
    }

}