package net.coding.api;

import javax.annotation.CheckForNull;
import java.io.IOException;
import java.net.URL;

public class HttpException extends IOException {

    private final int responseCode;
    private final String responseMessage;
    private final String url;

    public HttpException(int responseCode, String responseMessage, String url, Throwable cause) {
        super("Server returned HTTP response code: " + responseCode + ", message: '" + responseMessage + "'" +
                " for URL: " + url);
        initCause(cause);
        this.responseCode = responseCode;
        this.responseMessage = responseMessage;
        this.url = url;
    }

    public HttpException(int responseCode, String responseMessage, @CheckForNull URL url, Throwable cause) {
        this(responseCode, responseMessage, url == null ? null : url.toString(), cause);
    }
}
