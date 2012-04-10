package test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import net.sourceforge.scuba.smartcards.CardService;
import net.sourceforge.scuba.smartcards.CardServiceException;
import net.sourceforge.scuba.util.Hex;

public class EchoCardService extends CardService {
    private static final long serialVersionUID = -8709620488288623849L;

    public void open() throws CardServiceException {
        System.out.println("open() called");
    }

    public boolean isOpen() {
        System.out.println("isOpen() called");
        return true;
    }

    @Override
    public ResponseAPDU transmit(CommandAPDU apdu) throws CardServiceException {
        System.out.println("transmit(CommandAPDU) called");
        System.out.println(Hex.bytesToHexString(apdu.getBytes()));
        return new ResponseAPDU(new byte[]{(byte) 0x90, 0x00});
    }

    @Override
    public void close() {
        System.out.println("close() called");
    }
}
