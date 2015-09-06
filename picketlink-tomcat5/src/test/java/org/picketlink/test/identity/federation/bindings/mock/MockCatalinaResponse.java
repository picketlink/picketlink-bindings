package org.picketlink.test.identity.federation.bindings.mock;

import org.apache.catalina.connector.Response;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.Writer;
import java.util.HashMap;
import java.util.Map;

/**
 * Mock catalina response
 *
 * @author Anil.Saldhana@redhat.com
 * @since Oct 20, 2009
 */
public class MockCatalinaResponse extends Response {
    private Map<String, String> headers = new HashMap<String, String>();
    private int status;
    public String redirectString;
    private PrintWriter mywriter;
    private ServletOutputStream os;
    private ByteArrayOutputStream byteArray;

    @Override
    public void setCharacterEncoding(String charset) {
    }

    @Override
    public void setHeader(String name, String value) {
        this.headers.put(name, value);
    }

    @Override
    public int getStatus() {
        return this.status;
    }

    @Override
    public void setStatus(int status) {
        this.status = status;
    }

    @Override
    public void sendRedirect(String arg0) throws IOException {
        this.redirectString = arg0;
    }

    @Override
    public boolean isCommitted() {
        return false;
    }

    @Override
    public boolean isAppCommitted() {
        boolean redirected = getStatus() == HttpServletResponse.SC_MOVED_TEMPORARILY;
        return redirected;
    }

    public void setWriter(Writer w) {
        this.mywriter = (PrintWriter) w;
    }

    @Override
    public PrintWriter getWriter() throws IOException {
        return this.mywriter;
    }

    @Override
    public void setContentLength(int length) {
    }

    @Override
    public void setContentType(String arg0) {
    }

    @Override
    public void recycle() {
    }

    @Override
    public void resetBuffer() {
    }

    @Override
    public ServletOutputStream getOutputStream() throws IOException {
        return this.os;
    }

    public void setOutputStream(final ByteArrayOutputStream os) {
        this.byteArray = os;
        this.os = new ServletOutputStream() {
            @Override
            public void write(int b) throws IOException {
                os.write(b);
            }
        };
    }

    public ByteArrayOutputStream getByteArrayOutputStream() {
        return this.byteArray;
    }

    @Override
    public void reset() {
    }

    @Override
    public void addHeader(String name, String value) {
        this.headers.put(name,value);
    }

    @Override
    public void sendAcknowledgement() throws IOException {
    }
}
