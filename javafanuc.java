package javafanuc;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class Main {

    public static void main(String[] args) {
        byte[] n1=new byte[]{1,2,3,4,5,6,7,8};
        byte[] n2=new byte[]{9,10,11,12,13,14,15};
        byte[] h=encap(new byte[][] {n1,n2});
        for(byte b:h) {
            System.out.printf("0x%02x ",b);
        }
        System.out.println();
    }

    static byte[] encap(byte[][] payload) {
        ByteBuffer b=ByteBuffer.allocate(1500);
        b.order(ByteOrder.BIG_ENDIAN);
        b.putInt(0xa0a0a0a0); //Header
        b.putShort((short)1); //Version
        b.putShort((short)0x2101); //Request
        b.putShort((short)0); //Placeholder Length
        b.putShort((short)payload.length);

        for(byte[] t : payload) {
            b.putShort((short)(t.length+2));
            b.put(t);
        }

        b.putShort(8,(short)(b.position()-10));

        byte[] ret=new byte[b.position()];
        b.position(0);
        b.get(ret);
        return ret;
    }
}
