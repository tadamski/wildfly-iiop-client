/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015, Red Hat Middleware LLC, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

/**
 *  @author <a href="mailto:tadamski@redhat.com">Tomasz Adamski</a>
 */

package org.wildfly.iiiop.client;

import com.sun.corba.se.impl.orbutil.ORBConstants;
import com.sun.corba.se.pept.transport.Acceptor;
import com.sun.corba.se.spi.orb.ORB;
import com.sun.corba.se.spi.transport.ORBSocketFactory;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.KeyStore;

public class IIOPClientSocketFactory implements ORBSocketFactory {

    private static final String SSL_SOCKET_TYPE = "SSL";

    private ORB orb;

    private boolean clientAuth;
    private boolean requestMutualAuth;
    private boolean requireMutualAuth;

    private SSLContext sslContext;

    public IIOPClientSocketFactory(){}

    public static class Config {

        private boolean clientAuth = false;
        private boolean requestMutualAuth = false;
        private boolean requireMutualAuth = false;

        private String trustStoreType = "JKS";
        private String trustStorePath;
        private char[] trustStorePassword;

        private String keyStoreType = "JKS";
        private String keyStorePath;
        private char[] keyStorePassword;

        public void setClientAuth(boolean clientAuth) {
            this.clientAuth = clientAuth;
        }

        public void setRequestMutualAuth(boolean request_mutual_auth) {
            this.requestMutualAuth = request_mutual_auth;
        }

        public void setRequireMutualAuth(boolean require_mutual_auth) {
            this.requireMutualAuth = require_mutual_auth;
        }

        public Config setTrustStoreType(String trustStoreType) {
            this.trustStoreType = trustStoreType;
            return this;
        }

        public Config setTrustStorePath(String trustStorePath) throws IOException {
            this.trustStorePath = trustStorePath;
            return this;
        }

        public Config setTrustStorePassword(String trustStorePassword) {
            this.trustStorePassword = trustStorePassword.toCharArray();
            return this;
        }

        public void setKeyStoreType(String keyStoreType) {
            this.keyStoreType = keyStoreType;
        }

        public void setKeyStorePath(String keyStorePath) {
            this.keyStorePath = keyStorePath;
        }

        public void setKeyStorePassword(char[] keyStorePassword) {
            this.keyStorePassword = keyStorePassword;
        }
    }

    public static Config CONFIG = new Config();

    public void setORB(final ORB orb) {
        try {

            this.orb = orb;

            clientAuth = CONFIG.clientAuth;
            requestMutualAuth = CONFIG.requestMutualAuth;
            requireMutualAuth = CONFIG.requireMutualAuth;

            final KeyStore trustStore = KeyStore.Builder.newInstance(CONFIG.trustStoreType, null, new File(CONFIG.trustStorePath), new KeyStore.PasswordProtection(CONFIG.trustStorePassword)).getKeyStore();
            final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            final KeyStore keyStore = KeyStore.Builder.newInstance(CONFIG.keyStoreType, null, new File(CONFIG.keyStorePath), new KeyStore.PasswordProtection(CONFIG.keyStorePassword)).getKeyStore();
            final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, CONFIG.keyStorePassword);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
            this.sslContext = sslContext;
        } catch(Exception e){
            throw new IllegalStateException("Cannot instantiate ORBSocketFactory", e);
        }
    }

    public ServerSocket createServerSocket(final String type, final InetSocketAddress inetSocketAddress) throws IOException {
        final ServerSocketChannel serverSocketChannel;
        final ServerSocket serverSocket;

        if (type.equals(SSL_SOCKET_TYPE)) {
            serverSocket = createSSLServerSocket(inetSocketAddress.getPort(), 1000,
                    InetAddress.getByName(inetSocketAddress.getHostName()));
        } else if (orb.getORBData().acceptorSocketType().equals(ORBConstants.SOCKETCHANNEL)) {
            serverSocketChannel = ServerSocketChannel.open();
            serverSocket = serverSocketChannel.socket();
        } else {
            serverSocket = new ServerSocket();
        }
        if (!type.equals(SSL_SOCKET_TYPE)) {
            serverSocket.bind(inetSocketAddress);
        }
        return serverSocket;
    }

    public Socket createSocket(final String type, final InetSocketAddress inetSocketAddress) throws IOException {
        final SocketChannel socketChannel;
        final Socket socket;

        if (type.contains(SSL_SOCKET_TYPE)) {
            socket = createSSLSocket(inetSocketAddress.getHostName(), inetSocketAddress.getPort());
        } else if (orb.getORBData().connectionSocketType().equals(ORBConstants.SOCKETCHANNEL)) {
            socketChannel = SocketChannel.open(inetSocketAddress);
            socket = socketChannel.socket();
        } else {
            socket = new Socket(inetSocketAddress.getHostName(), inetSocketAddress.getPort());
        }

        // Disable Nagle's algorithm (i.e., always send immediately).
        socket.setTcpNoDelay(true);
        return socket;
    }

    public void setAcceptedSocketOptions(final Acceptor acceptor, final ServerSocket serverSocket, final Socket socket) throws SocketException {
        // Disable Nagle's algorithm (i.e., always send immediately).
        socket.setTcpNoDelay(true);
    }

    public Socket createSSLSocket(final String host, final int port) throws IOException {
        final InetAddress address = InetAddress.getByName(host);

        final SSLSocketFactory socketFactory = this.sslContext.getSocketFactory();
        final SSLSocket socket = (SSLSocket) socketFactory.createSocket(address, port);
        socket.setNeedClientAuth(true);
        return socket;
    }

    public ServerSocket createSSLServerSocket(final int port, final int backlog, final InetAddress inetAddress) throws IOException {
        final SSLServerSocketFactory serverSocketFactory = this.sslContext.getServerSocketFactory();
        final SSLServerSocket serverSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(port, backlog, inetAddress);

        if (clientAuth || this.requireMutualAuth)
            serverSocket.setNeedClientAuth(true);
        else
            serverSocket.setWantClientAuth(this.requestMutualAuth);

        return serverSocket;
    }
}
