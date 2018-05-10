package net.coding.api.extras;

import com.squareup.okhttp.OkUrlFactory;
import net.coding.api.HttpConnector;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

public class OkHttpConnector implements HttpConnector {
    private final OkUrlFactory urlFactory;

    public OkHttpConnector(OkUrlFactory urlFactory) {
        this.urlFactory = urlFactory;
    }

    public HttpURLConnection connect(URL url) throws IOException {
        return urlFactory.open(url);
    }
}
