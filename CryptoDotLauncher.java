/*
 * 
 *Many code snippets were provided by Research In Motion Ltd.
 *
 *GPL blah todo
 *
 */

package com.blah.CryptoDot;

import net.rim.device.api.crypto.CryptoTokenException;
import net.rim.device.api.crypto.CryptoUnsupportedOperationException;
import net.rim.device.api.crypto.UnsupportedCryptoSystemException;
import net.rim.device.api.crypto.keystore.KeyStoreCancelException;
import net.rim.device.api.crypto.keystore.KeyStoreDecodeException;
import net.rim.device.api.crypto.keystore.KeyStoreRegisterException;
import net.rim.device.api.ui.UiApplication;

public class CryptoDotLauncher extends UiApplication{
	public static void main(String[] args) throws KeyStoreRegisterException, KeyStoreCancelException,
	KeyStoreDecodeException, UnsupportedCryptoSystemException, CryptoTokenException, CryptoUnsupportedOperationException
	{
		CryptoDotLauncher theApp = new CryptoDotLauncher();
		theApp.enterEventDispatcher();
	}
	public CryptoDotLauncher() throws KeyStoreRegisterException, KeyStoreCancelException,
	KeyStoreDecodeException, UnsupportedCryptoSystemException, CryptoTokenException, CryptoUnsupportedOperationException
	{
		pushScreen(new CryptoDotMainScreen() );
	}

}
