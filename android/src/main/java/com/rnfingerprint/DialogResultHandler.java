package com.rnfingerprint;

import com.facebook.react.bridge.Callback;

public class DialogResultHandler implements FingerprintDialog.DialogResultListener {
    private Callback errorCallback;
    private Callback successCallback;

    public DialogResultHandler(Callback reactErrorCallback, Callback reactSuccessCallback) {
      errorCallback = reactErrorCallback;
      successCallback = reactSuccessCallback;
    }

    @Override
    public void onAuthenticated() {
      FingerprintAuthModule.inProgress = false;
      successCallback.invoke("Successfully authenticated.");
    }

    @Override
    public void onError(String errorString, int errorCode) {
      FingerprintAuthModule.inProgress = false;
      errorCallback.invoke(errorString, errorCode);
    }
    @Override
    public void onCancelled(Boolean isFallback) {
      FingerprintAuthModule.inProgress = false;
      if (isFallback) {
        errorCallback.invoke("fallback", FingerprintAuthConstants.AUTHENTICATION_CANCELED);
      } else {
        errorCallback.invoke("cancelled", FingerprintAuthConstants.AUTHENTICATION_CANCELED);
      }
    }
}
