/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package demo.wssec.server;

import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.bus.spring.SpringBusFactory;
import org.apache.cxf.jaxws.EndpointImpl;
import org.apache.cxf.ws.security.wss4j.WSS4JInInterceptor;

import javax.xml.ws.Endpoint;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

/**
 * A DOM-based server
 */
public class Server {
    private static final String WSSE_NS
        = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private static final String WSU_NS
        = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

    protected Server() throws Exception {
        System.out.println("Starting Server");

        Object implementor = new GreeterImpl();
        String address = "http://localhost:9000/SoapContext/GreeterPort";
        EndpointImpl endpoint = (EndpointImpl)Endpoint.publish(address, implementor);

        Map<String, Object> inProps = new HashMap<>();

        inProps.put("action", "SAMLTokenSigned");
        inProps.put("passwordCallbackClass", "demo.wssec.server.UTPasswordCallback");
        inProps.put("signaturePropFile", "etc/Server_SignVerf.properties");

        endpoint.getInInterceptors().add(new WSS4JInInterceptor(inProps));
    }

    public static void main(String[] args) throws Exception {

        SpringBusFactory bf = new SpringBusFactory();
        URL busFile = Server.class.getResource("wssec.xml");
        Bus bus = bf.createBus(busFile.toString());


        BusFactory.setDefaultBus(bus);

        new Server();
        System.out.println("Server ready...");

        Thread.sleep(5 * 60 * 1000);

        bus.shutdown(true);
        System.out.println("Server exiting");
        System.exit(0);
    }
}
