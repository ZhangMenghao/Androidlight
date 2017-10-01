package androidlight.vpn.tunnel;


import java.net.InetSocketAddress;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;

import androidlight.vpn.config.AndroidlightConfig;
import androidlight.vpn.config.Config;
import androidlight.vpn.config.HttpConnectConfig;
import androidlight.vpn.config.ProxyConfig;

public class TunnelFactory {

    public static Tunnel wrap(SocketChannel channel, Selector selector) {
        return new RawTunnel(channel, selector);
    }

    public static Tunnel createTunnelByConfig(InetSocketAddress destAddress, Selector selector) throws Exception {
        if (destAddress.isUnresolved()) {
            Config config = ProxyConfig.Instance.getDefaultTunnelConfig(destAddress);
            if (config instanceof HttpConnectConfig) {
                return new HttpConnectTunnel((HttpConnectConfig) config, selector);
            } else if (config instanceof AndroidlightConfig) {
                return new AndroidlightTunnel((AndroidlightConfig) config, selector);
            }
            throw new Exception("The config is unknow.");
        } else {
            return new RawTunnel(destAddress, selector);
        }
    }

}