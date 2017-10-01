package androidlight.vpn.tunnel;


import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;

import androidlight.vpn.core.LocalVpnService;
import androidlight.vpn.config.ProxyConfig;

public abstract class Tunnel {

    private final static ByteBuffer GL_BUFFER = ByteBuffer.allocate(20000);
    public static long SessionCount;

    protected abstract void onConnected(ByteBuffer buffer) throws Exception;

    protected abstract boolean isTunnelEstablished();

    protected abstract void beforeSend(ByteBuffer buffer) throws Exception;

    protected abstract void afterReceived(ByteBuffer buffer) throws Exception;

    protected abstract void onDispose();

    private SocketChannel m_InnerChannel;
    private ByteBuffer m_SendRemainBuffer;
    private Selector m_Selector;
    private Tunnel m_BrotherTunnel;
    private boolean m_Disposed;
    private InetSocketAddress m_ServerEP;
    protected InetSocketAddress m_DestAddress;

    Tunnel(SocketChannel innerChannel, Selector selector) {
        this.m_InnerChannel = innerChannel;
        this.m_Selector = selector;
        SessionCount++;
    }

    public Tunnel(InetSocketAddress serverAddress, Selector selector) throws IOException {
        SocketChannel innerChannel = SocketChannel.open();
        innerChannel.configureBlocking(false);
        this.m_InnerChannel = innerChannel;
        this.m_Selector = selector;
        this.m_ServerEP = serverAddress;
        SessionCount++;
    }

    public void setBrotherTunnel(Tunnel brotherTunnel) {
        m_BrotherTunnel = brotherTunnel;
    }

    public void connect(InetSocketAddress destAddress) throws Exception {
        if (LocalVpnService.Instance.protect(m_InnerChannel.socket())) {//保护socket不走vpn
            m_DestAddress = destAddress;
            m_InnerChannel.register(m_Selector, SelectionKey.OP_CONNECT, this);//注册连接事件
            m_InnerChannel.connect(m_ServerEP);//连接目标
        } else {
            throw new Exception("VPN protect socket failed.");
        }
    }

    protected void beginReceive() throws Exception {
        if (m_InnerChannel.isBlocking()) {
            m_InnerChannel.configureBlocking(false);
        }
        m_InnerChannel.register(m_Selector, SelectionKey.OP_READ, this);//注册读事件
    }


    protected boolean write(ByteBuffer buffer, boolean copyRemainData) throws Exception {
        int bytesSent;
        while (buffer.hasRemaining()) {
            bytesSent = m_InnerChannel.write(buffer);//buffer写入m_InnerChannel
            if (bytesSent == 0) {
                break;//不能再发送了，终止循环
            }
        }

        if (buffer.hasRemaining()) {//数据仍然没有发送完毕的话
            if (copyRemainData) {//拷贝剩余数据，然后侦听写入事件，待可写入时写入。
                //拷贝剩余数据
                if (m_SendRemainBuffer == null) {
                    m_SendRemainBuffer = ByteBuffer.allocate(buffer.capacity());
                }
                m_SendRemainBuffer.clear();
                m_SendRemainBuffer.put(buffer);
                m_SendRemainBuffer.flip();
                m_InnerChannel.register(m_Selector, SelectionKey.OP_WRITE, this);//注册写事件
            }
            return false;
        }
        else {//发送完毕了
            return true;
        }
    }

    protected void onTunnelEstablished() throws Exception {
        this.beginReceive();//开始接收数据
        m_BrotherTunnel.beginReceive();//兄弟也开始收数据吧
    }

    //可连接
    public void onConnectable() {
        try {
            if (m_InnerChannel.finishConnect()) {//连接成功
                onConnected(GL_BUFFER);//通知子类TCP已连接，子类可以根据协议实现握手等。
            }
            else {//连接失败
                LocalVpnService.Instance.writeLog("Error: connect to %s failed.", m_ServerEP);
                this.dispose();
            }
        } catch (Exception e) {
            LocalVpnService.Instance.writeLog("Error: connect to %s failed: %s", m_ServerEP, e);
            this.dispose();
        }
    }

    //可读
    public void onReadable(SelectionKey key) {
        try {
            ByteBuffer buffer = GL_BUFFER;
            buffer.clear();
            int bytesRead = m_InnerChannel.read(buffer);   //从m_InnerChannel中读入数据到buffer
            if (bytesRead > 0) {
                buffer.flip();   //buffer从从写模式切换到读模式
                afterReceived(buffer);//先让子类处理，例如解密数据。
                if (isTunnelEstablished() && buffer.hasRemaining()) {//将读到的数据，转发给兄弟。
                    m_BrotherTunnel.beforeSend(buffer);//发送之前，先让子类处理，例如做加密等。
                    if (!m_BrotherTunnel.write(buffer, true)) {//向m_BrotherTunnel写入buffer
                        key.cancel();//兄弟吃不消，就取消读取事件。
                        if (ProxyConfig.IS_DEBUG)
                            System.out.printf("%s can not read more.\n", m_ServerEP);
                    }
                }
            } else if (bytesRead < 0) {
                this.dispose();//连接已关闭，释放资源。
            }
        } catch (Exception e) {
            e.printStackTrace();
            this.dispose();
        }
    }

    //可写
    public void onWritable(SelectionKey key) {
        try {
            this.beforeSend(m_SendRemainBuffer);//发送之前，先让子类处理，例如做加密等。
            if (this.write(m_SendRemainBuffer, false)) {//如果剩余数据已经发送完毕
                key.cancel();//取消写事件。
                if (isTunnelEstablished()) {
                    m_BrotherTunnel.beginReceive();//这边数据发送完毕，通知兄弟可以收数据了。
                } else {
                    this.beginReceive();//开始接收代理服务器响应数据
                }
            }
        } catch (Exception e) {
            this.dispose();
        }
    }

    public void dispose() {
        disposeInternal(true);
    }

    private void disposeInternal(boolean disposeBrother) {
        if (m_Disposed) {
        }
        else {
            try {
                m_InnerChannel.close();
            } catch (Exception e) {
                e.printStackTrace();
            }

            if (m_BrotherTunnel != null && disposeBrother) {
                m_BrotherTunnel.disposeInternal(false);//把兄弟的资源也释放了。
            }

            m_InnerChannel = null;
            m_SendRemainBuffer = null;
            m_Selector = null;
            m_BrotherTunnel = null;
            m_Disposed = true;
            SessionCount--;

            onDispose();
        }
    }
}