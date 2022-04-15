package com.rnfingerprint;

import com.facebook.react.bridge.Callback;

public class DialogResultHandler implements FingerprintDialog.DialogResultListener {
    private Callback errorCallback;
    private Callback successCallback;
    private String fallbackError = null;

    public DialogResultHandler(Callback reactErrorCallback, Callback reactSuccessCallback) {
      errorCallback = reactErrorCallback;
      successCallback = reactSuccessCallback;
    }

    public void setFallbackError(String fallbackError) {
      this.fallbackError = fallbackError;
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
      if(isFallback && fallbackError != null) {
        errorCallback.invoke(this.fallbackError, FingerprintAuthConstants.AUTHENTICATION_CANCELED);
      } else {
        errorCallback.invoke("cancelled", FingerprintAuthConstants.AUTHENTICATION_CANCELED);
      }
    }
}
