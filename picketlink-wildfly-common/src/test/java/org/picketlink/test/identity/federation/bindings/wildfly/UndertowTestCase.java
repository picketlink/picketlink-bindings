package org.picketlink.test.identity.federation.bindings.wildfly;

import io.undertow.Undertow;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.PathHandler;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.DeploymentManager;
import io.undertow.servlet.api.LoginConfig;
import io.undertow.servlet.api.ServletContainer;
import io.undertow.servlet.api.ServletInfo;
import io.undertow.servlet.api.ServletSecurityInfo;
import io.undertow.util.Headers;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.ProtocolException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.DefaultRedirectStrategy;
import org.apache.http.protocol.HttpContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * Simple test for Undertow
 * @author Anil Saldhana
 * @since December 02, 2013
 */
public class UndertowTestCase {
    protected Undertow server = null;
    protected DefaultHttpClient httpClient = new DefaultHttpClient();

    protected HttpHandler getHandler(){
        return new  HttpHandler() {
            @Override
            public void handleRequest(final HttpServerExchange exchange) throws Exception {
                exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/plain");
                exchange.getResponseSender().send("Hello World");
            }
        };
    }

    protected void setupHttpClient(){
        httpClient.setRedirectStrategy(new DefaultRedirectStrategy() {
            @Override
            public boolean isRedirected(final HttpRequest request, final HttpResponse response, final HttpContext context) throws ProtocolException {
                if (response.getStatusLine().getStatusCode() == 302) {
                    return true;
                }
                return super.isRedirected(request, response, context);
            }
        });
    }

    @Before
    public void setup() throws Exception{
        Undertow.Builder builder = Undertow.builder().addListener(8080, "localhost");
        final PathHandler path = new PathHandler();

        server = builder.setHandler(getHandler()).build();

        server.start();
        System.out.println("Undertow server started");
        setupHttpClient();
    }

    @After
    public void tearDown() throws Exception{
        if(server != null){
            server.stop();
        }
    }

    @Test
    public void testServerUp() throws Exception{
        //Check if server is up
        String uri = "http://localhost:8080/";
        HttpGet get = new HttpGet(uri);

        HttpResponse result = httpClient.execute(get);
        assertEquals(200, result.getStatusLine().getStatusCode());
    }
}
