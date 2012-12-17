/**
 * 
 * 
 * Many code snippets were provided by Research In Motion Ltd.
 * 
 * Many better things were provided by the crypto.is community
 *
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


package com.blah.CryptoDot;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import com.blah.fields.HorizontalButtonFieldSet;

import net.rim.device.api.command.Command;
import net.rim.device.api.command.CommandHandler;
import net.rim.device.api.command.ReadOnlyCommandMetadata;
import net.rim.device.api.crypto.AESCTRDRBGPseudoRandomSource;
import net.rim.device.api.crypto.AESEncryptorEngine;
import net.rim.device.api.crypto.AESKey;
import net.rim.device.api.crypto.CTRPseudoRandomSource;
import net.rim.device.api.crypto.CryptoTokenException;
import net.rim.device.api.crypto.CryptoUnsupportedOperationException;
import net.rim.device.api.crypto.HMAC;
import net.rim.device.api.crypto.HMACKey;
import net.rim.device.api.crypto.InitializationVector;
import net.rim.device.api.crypto.InvalidKeyEncodingException;
import net.rim.device.api.crypto.InvalidKeyException;
import net.rim.device.api.crypto.MACOutputStream;
import net.rim.device.api.crypto.NoSuchAlgorithmException;
import net.rim.device.api.crypto.PKCS5KDF2PseudoRandomSource;
import net.rim.device.api.crypto.PRNGDecryptor;
import net.rim.device.api.crypto.PRNGEncryptor;
import net.rim.device.api.crypto.RandomSource;
import net.rim.device.api.crypto.SHA256Digest;
import net.rim.device.api.crypto.UnsupportedCryptoSystemException;
import net.rim.device.api.crypto.keystore.KeyStoreCancelException;
import net.rim.device.api.crypto.keystore.KeyStoreDecodeException;
import net.rim.device.api.crypto.keystore.KeyStoreException;
import net.rim.device.api.crypto.keystore.KeyStoreRegisterException;
import net.rim.device.api.io.NoCopyByteArrayOutputStream;
import net.rim.device.api.system.Clipboard;
import net.rim.device.api.ui.Manager;
import net.rim.device.api.ui.MenuItem;
import net.rim.device.api.ui.UiApplication;
import net.rim.device.api.ui.component.AutoTextEditField;
import net.rim.device.api.ui.component.ButtonField;
import net.rim.device.api.ui.component.Dialog;
import net.rim.device.api.ui.component.EditField;
import net.rim.device.api.ui.component.SeparatorField;
import net.rim.device.api.ui.component.StandardTitleBar;
import net.rim.device.api.ui.container.MainScreen;
import net.rim.device.api.ui.container.VerticalFieldManager;
import net.rim.device.api.util.Arrays;
import net.rim.device.api.util.DataBuffer;
import net.rim.device.api.util.StringProvider;

	// TODO zrtp srtp , learn to genereate unique id's for each contact 
	// generate session key for each message

public class CryptoDotMainScreen extends MainScreen {

	private EditField _EncryptedField;
	private EditField _DecryptedField;
	private AutoTextEditField _inputField;
	private EditField _PassphraseField;
	// private PasswordEditField _PassphraseField;
	// TODO ^^
	private EditField _IvField;
	private EditField _FullMessage;
	private EditField _MacField;
	private EditField _MessageLen;
	private final String _empty = "";
	private final int _mustBe16 = 16;
	// TODO get rid of _IvField when done testing
	

    public static void main( String[] args ) throws UnsupportedCryptoSystemException,
    CryptoTokenException, CryptoUnsupportedOperationException, KeyStoreRegisterException, KeyStoreCancelException, KeyStoreException
    {
    	CryptoDotLauncher theApp = new CryptoDotLauncher();
    	theApp.enterEventDispatcher();
    }


    
    public CryptoDotMainScreen() throws UnsupportedCryptoSystemException, CryptoTokenException,
    CryptoUnsupportedOperationException, KeyStoreRegisterException, KeyStoreCancelException, KeyStoreDecodeException
    {
    	// TODO 
    	// Add HMAC (Message Authentication Code) to messages (1st step done)
    	// Byte Array for salt, password and method for IV
    	// Read J-PAKE
    	// D-H to generate a shared secret
    	// srtp and zrtp ?
    	// forward secret ?
    	// wipe Password as soon as it gets hashed
    	// ? set strings to null ?
    	// rename to have consistent, makes less confusing for me too
    	// use AESCTRDRBGPseudoRandomSource to replace randomsource ? needs a salt!
    
    	
    	final VerticalFieldManager _vfm = (VerticalFieldManager)getMainManager();

    	StandardTitleBar myTitleBar = new StandardTitleBar()
    	.addTitle("FirstCryptoDotCTR-MAC")
    	.addClock()
    	.addNotifications()
    	.addSignalIndicator();
    	myTitleBar.setPropertyValue(StandardTitleBar.PROPERTY_BATTERY_VISIBILITY,
    			StandardTitleBar.BATTERY_VISIBLE_ALWAYS	);
    	setTitleBar(myTitleBar);

		_inputField = new AutoTextEditField("ClearText: ", "");
    	_inputField.isSpellCheckable();
    	_vfm.add(_inputField);
    	_vfm.add(new SeparatorField());

        _PassphraseField = new EditField("Passphrase: ", "");
        _vfm.add(_PassphraseField);
        _vfm.add(new SeparatorField());
        
        _IvField = new EditField("Iv: ", "");
        _vfm.add(_IvField);
        _vfm.add(new SeparatorField());
        
        _MacField = new EditField("MAC: ", "");
        _vfm.add(_MacField);
        _vfm.add(new SeparatorField());
        
        _EncryptedField = new EditField("EnCrypted: ", "");
        _vfm.add(_EncryptedField);
        _vfm.add(new SeparatorField());
        
        _DecryptedField = new EditField("DeCrypted: ", "");
        _vfm.add(_DecryptedField);
        _vfm.add(new SeparatorField());
        
        _FullMessage = new EditField("Message: ", "");
        _vfm.add(_FullMessage);
        _vfm.add(new SeparatorField());
        
        _MessageLen = new EditField("Length: ", "");
        _vfm.add(_MessageLen);
        _vfm.add(new SeparatorField());
        
        HorizontalButtonFieldSet setOne = new HorizontalButtonFieldSet(Manager.HORIZONTAL_SCROLL);
        
        ButtonField _encryptButton = new ButtonField("Encrypt"){
        	public boolean trackwheelClick(int status, int time){
        		String text = _inputField.getText();
        		if(text.length() > 0){
        			try {
        				runEncrypt(text);
        				_vfm.setFocus();
        				Clipboard _cp = Clipboard.getClipboard();
        				_cp.put(null);
        			} catch (InvalidKeyException e) {
        				e.printStackTrace();
        			} catch (UnsupportedCryptoSystemException e) {
        				e.printStackTrace();
        			} catch (KeyStoreCancelException e) {
        				e.printStackTrace();
        			} catch (KeyStoreDecodeException e) {
        				e.printStackTrace();
        			} catch (NoSuchAlgorithmException e) {
        				e.printStackTrace();
        			} catch (InvalidKeyEncodingException e) {
        				e.printStackTrace();
        			}
        		}else{
        			Dialog.alert("Cleartext Empty");
        		}
        		return true; 
        	}
        };

        ButtonField _clearButton = new ButtonField("Clear"){
        	public boolean trackwheelClick(int status, int time){
        		_inputField.clear(0);
        		_EncryptedField.clear(0);
        		_DecryptedField.clear(0);
        		_PassphraseField.clear(0);
        		_inputField.setFocus();
        		_FullMessage.clear(0);
        		_MacField.clear(0);
        		Clipboard _cp = Clipboard.getClipboard();
        		_cp.put(null);
        		return true;
        	}
        };

        _encryptButton.setMargin( 10, 5, 5, 5 );
        _clearButton.setMargin( 10, 5, 5, 5 );

        setOne.add( _encryptButton );
        setOne.add( _clearButton );
        add( setOne );

        HorizontalButtonFieldSet setTwo = new HorizontalButtonFieldSet(Manager.HORIZONTAL_SCROLL);

        ButtonField decryptButton = new ButtonField("Decrypt"){
        	public boolean trackwheelClick(int status, int time){
        		String text = _FullMessage.getText();
        		if(text.length() > 0){
        			runDecrypt(text);
        			_DecryptedField.setFocus();
        			Clipboard _cp = Clipboard.getClipboard();
        			_cp.put(null);
        		}else{
        			Dialog.alert("Message Area Empty");
        		}                
        		return true; 
        	}
        };
        ButtonField copyButton = new ButtonField("Copy"){
        	public boolean trackwheelClick(int status, int time){
        		String _clip = _FullMessage.getText();
        		if(_clip.length() > 0){
        			Clipboard _cp = Clipboard.getClipboard();
        			_cp.put(null);
        			_cp.put(_clip);
        			Dialog.alert("Cipher > Clipboard");
        		}else{
        			Dialog.alert("Nothing to Copy");
        		}
        		return true; 
        	}
        };

        decryptButton.setMargin( 5, 5, 5, 5 );
        copyButton.setMargin(5, 5, 5, 5 );
        setTwo.add(decryptButton);
        setTwo.add(copyButton);
        add( setTwo );

        MenuItem Encrypt = new MenuItem(new StringProvider("Encrypt") , 0x230010, 0);
        Encrypt.setCommand(new Command(new CommandHandler() {
        	public void execute(ReadOnlyCommandMetadata metadata, Object context) {
        		String text = _inputField.getText();
        		if(text.length() > 0){
        			try {
        				runEncrypt(text);
        				_inputField.setFocus();
        				Clipboard _cp = Clipboard.getClipboard();
        				_cp.put(null);
        			} catch (KeyStoreCancelException e) {
        				e.printStackTrace();
        			} catch (KeyStoreDecodeException e) {
        				e.printStackTrace();
        			} catch (InvalidKeyException e) {
        				e.printStackTrace();
        			} catch (UnsupportedCryptoSystemException e) {
        				e.printStackTrace();
        			} catch (NoSuchAlgorithmException e) {
        				e.printStackTrace();
        			} catch (InvalidKeyEncodingException e) {
        				e.printStackTrace();
        			}
        		}else{
        			Dialog.alert("Cleartext Empty");
        		}                
        	}
        }));

        MenuItem Decrypt = new MenuItem(new StringProvider("Decrypt") , 0x230010, 10);
        Decrypt.setCommand(new Command(new CommandHandler() {
        	public void execute(ReadOnlyCommandMetadata metadata, Object context) {
        		String text = _FullMessage.getText();
        		if(text.length() > 0){
        			runDecrypt(text);
        			Clipboard _cp = Clipboard.getClipboard();
        			_cp.put(null);
        			_DecryptedField.setFocus();
        		}else{
        			Dialog.alert("Message Area Empty");
        		}                
        	}
        }));


        MenuItem Clear = new MenuItem(new StringProvider("Clear") , 0x230010, 20);
        Clear.setCommand(new Command(new CommandHandler() {
        	public void execute(ReadOnlyCommandMetadata metadata, Object context) {
        		_inputField.clear(0);
        		_EncryptedField.clear(0);
        		_DecryptedField.clear(0);
        		_PassphraseField.clear(0);
        		_inputField.setFocus();
        		_FullMessage.clear(0);
        		_MacField.clear(0);
        		Clipboard _cp = Clipboard.getClipboard();
        		_cp.put(null);
        	}
        }));

        MenuItem Copy = new MenuItem(new StringProvider("Copy") , 0x230010, 30);
        Copy.setCommand(new Command(new CommandHandler(){
        	public void execute(ReadOnlyCommandMetadata metadata, Object context){
        		String _clip = _FullMessage.getText();
        		if(_clip.length() > 0){
        			Clipboard _cp = Clipboard.getClipboard();
        			_cp.put(null);
        			_cp.put(_clip);
        			Dialog.alert("Cyphertext > Clipboard"); 
        		}else{
        			Dialog.alert("Nothing to Copy");
        		}
        	}
        }));
        

        addMenuItem(Encrypt);
        addMenuItem(Decrypt);
        addMenuItem(Clear);
        addMenuItem(Copy);
    }

    

    private void runEncrypt(String text) throws InvalidKeyException, UnsupportedCryptoSystemException,
    KeyStoreCancelException, KeyStoreDecodeException, NoSuchAlgorithmException, InvalidKeyEncodingException{
    	try{
    		String textKey = _PassphraseField.getText();
    		int _length = textKey.length();
    		if(textKey.equals(_empty) ) {
    			Dialog.alert("wtf? No Passphrase, No Encryption.");
    		}else if(_length < _mustBe16) {
    			Dialog.alert("Your Passphrase must be 16 characters or longer.");
    		}else{
    		
            String _testString = stringToHex(textKey);
            String _combString = (_testString + _testString + _testString + _testString);
            
            byte[] filler = RandomSource.getBytes(64);
            String fillerIv = byteArrayToHexString(filler);
        	String dash = "-";
        	// int fillLen = filler.length;
        	
            String IvStringSub = fillerIv.substring(0, 64);
            int fillLen = IvStringSub.length();
            _IvField.setText(IvStringSub + fillLen);
            byte[] salt = hexToByteArray(_testString);
            byte[] password = hexToByteArray(_combString);
            byte[] _ivEr = hexToByteArray(IvStringSub);
           
            // TODO -
            // How many times to hash block?? set at 100,000. 
            // Increase hash iterations to noticebly slow down device, find a medium.
            
            PKCS5KDF2PseudoRandomSource _prs = new PKCS5KDF2PseudoRandomSource(password, salt, 1);
            byte[] _hashed = _prs.getBytes(256);
            //PBKDF2 _pbkdf = new PBKDF2();
           	
            AESKey aesKey = new AESKey(_hashed, 0, 256);
            InitializationVector _iv = new InitializationVector(_ivEr);
            
            AESEncryptorEngine _engine1 = new AESEncryptorEngine(aesKey, 32, true, true );
            // research CPAprotection and FIPSmode
            CTRPseudoRandomSource source = new CTRPseudoRandomSource(_engine1, _iv);
            NoCopyByteArrayOutputStream outputStream = new NoCopyByteArrayOutputStream();
            PRNGEncryptor encStream = new PRNGEncryptor(source, outputStream);
            
            byte[] textByteses = text.getBytes();
            int enLen = textByteses.length ;
            encStream.write( textByteses, 0, enLen);
            encStream.close();
            outputStream.close();
            int outLen = outputStream.size();
            byte[] encryptedData = outputStream.toByteArray();
            System.arraycopy(outputStream.getByteArray(), 0, encryptedData, 0, outLen);

            HMACKey key = new HMACKey(_hashed);
            SHA256Digest digest = new SHA256Digest();
            HMAC hMac = new HMAC( key, digest);
            MACOutputStream macOut = new MACOutputStream(hMac, null);
            macOut.write(encryptedData);
            macOut.close();
            byte[] macValue = hMac.getMAC();
            String MacCode = byteArrayToHexString(macValue);
            int macLength = MacCode.length();
            _MacField.setText(MacCode + macLength);
            
            // End of Encryption
            //-----------------------------------------------------------------------------------------------
            // Beginning of Decryption
            
            ByteArrayInputStream inputStream = new ByteArrayInputStream( encryptedData );
            CTRPseudoRandomSource source2 = new CTRPseudoRandomSource(_engine1, _iv);
            PRNGDecryptor decStream = new PRNGDecryptor(source2, inputStream);

            byte[] data = new byte[outLen];
            decStream.read(data, 0, outLen);
            decStream.close();
            inputStream.close();
            String rslt = byteArrayToHexString(encryptedData);
            String fullText = (MacCode + IvStringSub + rslt);
            int rsltLen = rslt.length();
            int total = (macLength + fillLen + rsltLen);
            
            // fillLen + macLength + rsltLen
            _MessageLen.setText(_empty + total);
            
            byte[] textBytes = text.getBytes();
            byte[] decBytes = data;
            if( Arrays.equals( text.getBytes(), data ) ) {
            	_EncryptedField.setText(rslt);
            	_FullMessage.setText(fullText);
            	_inputField.clear(0);
            	_PassphraseField.clear(0);
            	_DecryptedField.clear(0);
            }else{
            	Dialog.alert("Doesn't add up.");
            	_inputField.clear(0);
            	_PassphraseField.clear(0);
            	_DecryptedField.clear(0);
            }
    		}
    	}catch( CryptoTokenException e ) {
    		errorDialog(e.toString());
    	}catch (CryptoUnsupportedOperationException e) {
    		errorDialog(e.toString());
    	}catch( IOException e ) {
    		errorDialog(e.toString());
    	}
    }

   
	private void runDecrypt(String cyphertext){
    	try {
    		String _fullMessage = cyphertext;
    		int _lengthO = _fullMessage.length();
    		
    		String _macStringSub = _fullMessage.substring(0, 64);
    		String IvStringSub = _fullMessage.substring(64, 128);
    		String _partMessage = _fullMessage.substring(128, _lengthO);
    		String _macToCheck = _fullMessage.substring(32, _lengthO);
    		int _macStringLength = _macStringSub.length();
    		int IvStringLength = IvStringSub.length();
    		int _partMessLength = _partMessage.length();

    		byte[] macBytes = hexToByteArray(_macStringSub);

    		byte[] rc = hexToByteArray(_partMessage);
    		// String _empty = "";
    		String textKey = _PassphraseField.getText();
    		int _length = textKey.length();
    		// int _mustBe16 = 16;
    		if(textKey.equals(_empty) ) {
    			Dialog.alert("wtf? No Passphrase, No Decryption.");
    		}else if(_length < _mustBe16) {
    			Dialog.alert("Your Passphrase must be 16 characters or longer.");
    		}else{
    		
            String _testString = stringToHex(textKey);
            String _combString = (_testString + _testString + _testString + _testString);
            byte[] salt = hexToByteArray(_testString);
            byte[] password = hexToByteArray(_combString);
            
            byte[] _ivErs = hexToByteArray(IvStringSub);
            //How many times to hash ?? set at 100,000. 
            
            PKCS5KDF2PseudoRandomSource _prs = new PKCS5KDF2PseudoRandomSource(password, salt, 1);
            byte[] _hashed = _prs.getBytes(256);
            
            //PBKDF2 _pbk = new PBKDF2();
            AESKey aesKey = new AESKey(_hashed, 0, 256);
            
            HMACKey key = new HMACKey(_hashed);
            SHA256Digest digest = new SHA256Digest();
            HMAC hMac = new HMAC( key, digest);
            MACOutputStream macOut = new MACOutputStream(hMac, null);
            byte[] three = rc;
            macOut.write(three);
            macOut.close();
            byte[] macValue = hMac.getMAC();
            String MacCode = byteArrayToHexString(macValue);
            
            // _MacField.setText(MacCode);
            if(Arrays.equals(macValue, macBytes)){

            	InitializationVector _ivs = new InitializationVector(_ivErs);
            	ByteArrayInputStream inputStreams = new ByteArrayInputStream( rc );

            	AESEncryptorEngine _engine2s= new AESEncryptorEngine(aesKey, 32, true, true );
            	CTRPseudoRandomSource sources = new CTRPseudoRandomSource(_engine2s, _ivs);
            	PRNGDecryptor decStreams = new PRNGDecryptor(sources, inputStreams);

            	byte[] temps = new byte[64];
            	DataBuffer dbs = new DataBuffer();

            	for( ;; ) {
            		int bytesRead = decStreams.read( temps );
            		if( bytesRead <= 0 ){
            			break;
            		}
            		dbs.write(temps, 0, bytesRead);
            	}

            	byte[] decryptedData = dbs.toArray();
            	decStreams.close();
            	inputStreams.close();
            	String decryptedText = new String(decryptedData);
            	_PassphraseField.clear(0);
            	//_cypherField.clear(0);
            	_EncryptedField.clear(0);
            	_inputField.clear(0);
            	_DecryptedField.setText( decryptedText);

            }else{
            	Dialog.alert("Message has been tampered with");
            }
    		}
    	}catch( CryptoTokenException e ) {
    		errorDialog(e.toString());
    	}catch (CryptoUnsupportedOperationException e) {
    		errorDialog(e.toString());
    	}catch( IOException e ) {
    		errorDialog(e.toString());


    	}
	}

	public static byte[] hexToByteArray(String cyphertext) {
    	byte rc[] = new byte[cyphertext.length() / 2];
    	for (int i = 0; i < rc.length; i++) {
    		String h = cyphertext.substring(i *2, i * 2 + 2);
    		int x = Integer.parseInt(h, 16);
    		rc[i] = (byte) x;
    	}return rc;
    }
    
    private static String HEXCHARS[] = {
    	"0", "1", "2", "3",
    	"4", "5", "6", "7",
    	"8", "9", "A", "B",
    	"C", "D", "E", "F"
    }; 
    
    private String stringToHex(String textKey) {
    	char[] chars = textKey.toCharArray();
    	StringBuffer strBuffer = new StringBuffer();
    	for (int i = 0; i < chars.length; i++){
    		strBuffer.append(Integer.toHexString( (int) chars[i] ) );
    	}
    	return strBuffer.toString();
    	
	}

    public static String byteArrayToHexString(byte outputStream[]) {
    	byte ch = 0x00;
    	int i = 0;
    	if (outputStream == null || outputStream.length <= 0) {
    		return null;
    	}

    	StringBuffer out = new StringBuffer(outputStream.length * 2);
    	while (i < outputStream.length) {
    		ch = (byte) (outputStream[i] & 0xF0);
    		ch = (byte) (ch >>> 4);
    		ch = (byte) (ch & 0x0F);
    		out.append(HEXCHARS[ (int) ch]); 
    		ch = (byte) (outputStream[i] & 0x0F); 
    		out.append(HEXCHARS[ (int) ch]); 
    		i++;
    	}
    	String rslt = out.toString();
    	return rslt;
    }

    // onClose()
    // clear out fields 
    // also wipe Strings and others
    
    public boolean onClose(){
    	_EncryptedField.clear(0);
    	_DecryptedField.clear(0);
    	_inputField.clear(0);
    	//_cypherField.clear(0);
    	_MacField.clear(0);
    	_PassphraseField.clear(0);
    	_IvField.clear(0);
    	_FullMessage.clear(0);
    	
		Dialog.alert("gtfo");
		System.exit(0);
    	return true;
    	
    }
    
    public static void errorDialog(final String message){
    	UiApplication.getUiApplication().invokeLater(new Runnable(){
    		public void run(){
    			Dialog.alert(message);
    		} 
    	});
    }

}
