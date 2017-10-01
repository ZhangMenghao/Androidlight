package androidlight.vpn.core;

import android.util.SparseArray;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;     //UDP的Socket
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.concurrent.ConcurrentHashMap;   //多线程下的HashMap

import androidlight.vpn.config.ProxyConfig;
import androidlight.vpn.dns.DNSPacket;
import androidlight.vpn.dns.Question;
import androidlight.vpn.dns.Resource;
import androidlight.vpn.dns.ResourcePointer;
import androidlight.vpn.tcpip.CommonMethods;
import androidlight.vpn.tcpip.IPHeader;
import androidlight.vpn.tcpip.UDPHeader;

//DNS代理
public class DNSProxy implements Runnable {

    private class QueryState {
        public short ClientQueryID;
        public long QueryNanoTime;
        public int ClientIP;
        public short ClientPort;
        public int RemoteIP;
        public short RemotePort;
    }

    public boolean Stopped;
    private static final ConcurrentHashMap<Integer, String> IPDomainMaps = new ConcurrentHashMap<Integer, String>();
    private static final ConcurrentHashMap<String, Integer> DomainIPMaps = new ConcurrentHashMap<String, Integer>();
    private final long QUERY_TIMEOUT_NS = 10 * 1000000000L;
    private DatagramSocket m_Client;
    private Thread m_ReceivedThread;
    private short m_QueryID;
    private SparseArray<QueryState> m_QueryArray;

    public DNSProxy() throws IOException {
        m_QueryArray = new SparseArray<QueryState>();
        m_Client = new DatagramSocket(0);
    }

    //反向DNS查询,由IP查询Domain
    public static String reverseLookup(int ip) {
        return IPDomainMaps.get(ip);
    }

    // 开始运行DNSProxy线程
    public void start() {
        m_ReceivedThread = new Thread(this);
        m_ReceivedThread.setName("DNSProxyThread");
        m_ReceivedThread.start();
    }

    //结束运行DNSProxy线程
    public void stop() {
        Stopped = true;
        if (m_Client != null) {
            m_Client.close();
            m_Client = null;
        }
    }

    // while循环负责监听客户端并接收来自其的报文并检查所携带的DNS应答报文
    @Override
    public void run() {
        try {
            byte[] RECEIVE_BUFFER = new byte[2000];
            IPHeader ipHeader = new IPHeader(RECEIVE_BUFFER, 0);
            ipHeader.Default();
            UDPHeader udpHeader = new UDPHeader(RECEIVE_BUFFER, 20);

            ByteBuffer dnsBuffer = ByteBuffer.wrap(RECEIVE_BUFFER);
            dnsBuffer.position(28);
            dnsBuffer = dnsBuffer.slice();

            DatagramPacket packet = new DatagramPacket(RECEIVE_BUFFER, 28, RECEIVE_BUFFER.length - 28);

            while (m_Client != null && !m_Client.isClosed()) {

                packet.setLength(RECEIVE_BUFFER.length - 28);
                m_Client.receive(packet);

                dnsBuffer.clear();
                dnsBuffer.limit(packet.getLength());
                try {
                    DNSPacket dnsPacket = DNSPacket.FromBytes(dnsBuffer);
                    if (dnsPacket != null) {
                        OnDnsResponseReceived(ipHeader, udpHeader, dnsPacket);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    LocalVpnService.Instance.writeLog("Parse dns error: %s", e);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            System.out.println("DNSResolver Thread Exited.");
            this.stop();
        }
    }

    //获取DNS报文的查询到的IP信息,默认取第一条Resource
    private int getFirstIP(DNSPacket dnsPacket) {
        for (int i = 0; i < dnsPacket.Header.ResourceCount; i++) {
            Resource resource = dnsPacket.Resources[i];
            //IPv4地址
            if (resource.Type == 1) {
                int ip = CommonMethods.readInt(resource.Data, 0);
                return ip;
            }
        }
        return 0;
    }

    //劫持并修改DNS响应报文中的IP地址
    private void tamperDnsResponse(byte[] rawPacket, DNSPacket dnsPacket, int newIP) {
        Question question = dnsPacket.Questions[0];

        dnsPacket.Header.setResourceCount((short) 1);
        dnsPacket.Header.setAResourceCount((short) 0);
        dnsPacket.Header.setEResourceCount((short) 0);

        ResourcePointer rPointer = new ResourcePointer(rawPacket, question.Offset() + question.Length());
        rPointer.setDomain((short) 0xC00C); //指针
        rPointer.setType(question.Type);
        rPointer.setClass(question.Class);
        rPointer.setTTL(ProxyConfig.Instance.getDnsTTL());
        rPointer.setDataLength((short) 4);
        rPointer.setIP(newIP);

        dnsPacket.Size = 12 + question.Length() + 16;
    }

    //创建或获取虚假IP
    private int getOrCreateFakeIP(String domainString) {
        Integer fakeIP = DomainIPMaps.get(domainString);
        if (fakeIP == null) {
            int hashIP = domainString.hashCode();
            do {
                fakeIP = ProxyConfig.FAKE_NETWORK_IP | (hashIP & 0x0000FFFF);
                hashIP++;
            } while (IPDomainMaps.containsKey(fakeIP));

            DomainIPMaps.put(domainString, fakeIP);
            IPDomainMaps.put(fakeIP, domainString);
        }
        return fakeIP;
    }

    //检测是否为DNS污染,修改成fakeIP
    private boolean dnsPollution(byte[] rawPacket, DNSPacket dnsPacket) {
        if (dnsPacket.Header.QuestionCount > 0) {
            Question question = dnsPacket.Questions[0];
            //查询IPv4地址
            if (question.Type == 1) {
                int realIP = getFirstIP(dnsPacket);
                //是否需要代理
                if (ProxyConfig.Instance.needProxy(question.Domain, realIP)) {
                    int fakeIP = getOrCreateFakeIP(question.Domain);
                    System.out.printf("The fakeip is %s\n", CommonMethods.ipIntToString(fakeIP));
                    tamperDnsResponse(rawPacket, dnsPacket, fakeIP);
                    if (ProxyConfig.IS_DEBUG)
                        System.out.printf("FakeDns: %s=>%s(%s)\n", question.Domain, CommonMethods.ipIntToString(realIP), CommonMethods.ipIntToString(fakeIP));
                    return true;
                }
            }
        }
        return false;
    }

    // 处理接收到的DNS响应报文后的处理
    private void OnDnsResponseReceived(IPHeader ipHeader, UDPHeader udpHeader, DNSPacket dnsPacket) {
        QueryState state = null;
        // 同步锁！
        synchronized (m_QueryArray) {
            state = m_QueryArray.get(dnsPacket.Header.ID);
            if (state != null) {
                m_QueryArray.remove(dnsPacket.Header.ID);
            }
        }

        if (state != null) {
            // DNS污染，默认污染海外网站
            dnsPollution(udpHeader.m_Data, dnsPacket);

            dnsPacket.Header.setID(state.ClientQueryID);
            ipHeader.setSourceIP(state.RemoteIP);
            ipHeader.setDestinationIP(state.ClientIP);
            ipHeader.setProtocol(IPHeader.UDP);
            ipHeader.setTotalLength(20 + 8 + dnsPacket.Size);
            udpHeader.setSourcePort(state.RemotePort);
            udpHeader.setDestinationPort(state.ClientPort);
            udpHeader.setTotalLength(8 + dnsPacket.Size);

            LocalVpnService.Instance.sendUDPPacket(ipHeader, udpHeader);
        }
    }

    //从Cache中获取DNS查询信息
    private int getIPFromCache(String domain) {
        Integer ip = DomainIPMaps.get(domain);
        if (ip == null) {
            return 0;
        } else {
            return ip;
        }
    }

    //拦截DNS
    private boolean interceptDns(IPHeader ipHeader, UDPHeader udpHeader, DNSPacket dnsPacket) {
        Question question = dnsPacket.Questions[0];
        System.out.println("DNS Qeury: " + question.Domain);
        //IPv4查询
        if (question.Type == 1) {
            //判断是否需要代理
            if (ProxyConfig.Instance.needProxy(question.Domain, getIPFromCache(question.Domain))) {
                int fakeIP = getOrCreateFakeIP(question.Domain);
                tamperDnsResponse(ipHeader.m_Data, dnsPacket, fakeIP);

                if (ProxyConfig.IS_DEBUG)
                    System.out.printf("interceptDns FakeDns: %s=>%s\n", question.Domain, CommonMethods.ipIntToString(fakeIP));
                //需要代理的话,劫持并修改DNS响应报文,发回源地址
                int sourceIP = ipHeader.getSourceIP();
                short sourcePort = udpHeader.getSourcePort();
                ipHeader.setSourceIP(ipHeader.getDestinationIP());
                ipHeader.setDestinationIP(sourceIP);
                ipHeader.setTotalLength(20 + 8 + dnsPacket.Size);
                udpHeader.setSourcePort(udpHeader.getDestinationPort());
                udpHeader.setDestinationPort(sourcePort);
                udpHeader.setTotalLength(8 + dnsPacket.Size);
                LocalVpnService.Instance.sendUDPPacket(ipHeader, udpHeader);
                return true;
            }
        }
        return false;
    }

    //清除过期DNS查询操作信息
    private void clearExpiredQueries() {
        long now = System.nanoTime();
        for (int i = m_QueryArray.size() - 1; i >= 0; i--) {
            QueryState state = m_QueryArray.valueAt(i);
            if ((now - state.QueryNanoTime) > QUERY_TIMEOUT_NS) {
                m_QueryArray.removeAt(i);
            }
        }
    }

    //接收DNS请求报文的操作
    public void onDnsRequestReceived(IPHeader ipHeader, UDPHeader udpHeader, DNSPacket dnsPacket) {
        //若不需要代理直接转发
        if (!interceptDns(ipHeader, udpHeader, dnsPacket)) {
            // 直接转发DNS请求报文
            QueryState state = new QueryState();
            state.ClientQueryID = dnsPacket.Header.ID;
            state.QueryNanoTime = System.nanoTime();
            state.ClientIP = ipHeader.getSourceIP();
            state.ClientPort = udpHeader.getSourcePort();
            state.RemoteIP = ipHeader.getDestinationIP();
            state.RemotePort = udpHeader.getDestinationPort();

            // 转换QueryID
            m_QueryID++;
            dnsPacket.Header.setID(m_QueryID);

            synchronized (m_QueryArray) {
                // 清空过期的查询，减少内存开销。
                clearExpiredQueries();
                m_QueryArray.put(m_QueryID, state);
            }

            InetSocketAddress remoteAddress = new InetSocketAddress(CommonMethods.ipIntToInet4Address(state.RemoteIP), state.RemotePort);
            DatagramPacket packet = new DatagramPacket(udpHeader.m_Data, udpHeader.m_Offset + 8, dnsPacket.Size);
            packet.setSocketAddress(remoteAddress);

            try {
                if (LocalVpnService.Instance.protect(m_Client)) {
                    m_Client.send(packet);
                } else {
                    System.err.println("VPN protect udp socket failed.");
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
