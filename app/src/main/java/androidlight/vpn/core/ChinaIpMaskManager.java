package androidlight.vpn.core;

import android.util.SparseIntArray;

import java.io.IOException;
import java.io.InputStream;

import androidlight.vpn.tcpip.CommonMethods;

public class ChinaIpMaskManager {

    static SparseIntArray ChinaIpMaskDict = new SparseIntArray(3000);
    static SparseIntArray MaskDict = new SparseIntArray();

    //检查IP是否在国内
    public static boolean isIPInChina(int ip) {
        boolean found = false;
        for (int i = 0; i < MaskDict.size(); i++) {
            int mask = MaskDict.keyAt(i);
            int networkIP = ip & mask;
            int mask2 = ChinaIpMaskDict.get(networkIP);
            if (mask2 == mask) {
                found = true;
                break;
            }
        }
        return found;
    }

    // read china ip information from input file
    public static void loadFromFile(InputStream inputStream) {
        int count = 0;
        try {
            byte[] buffer = new byte[4096];
            while ((count = inputStream.read(buffer)) > 0) {
                for (int i = 0; i < count; i += 8) {
                    int ip = CommonMethods.readInt(buffer, i);
                    int mask = CommonMethods.readInt(buffer, i + 4);
                    ChinaIpMaskDict.put(ip, mask);
                    MaskDict.put(mask, mask);
                    //System.out.printf("The ip is %s, the mask is %s\n", CommonMethods.ipIntToString(ip), CommonMethods.ipIntToString(mask));
                }
            }
            inputStream.close();
            System.out.printf("ChinaIpMask records count: %d\n", ChinaIpMaskDict.size());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
