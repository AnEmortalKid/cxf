package demo.wssec.client;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.bean.AttributeBean;
import org.apache.wss4j.common.saml.bean.AttributeStatementBean;
import org.apache.wss4j.common.saml.bean.AuthenticationStatementBean;
import org.apache.wss4j.common.saml.bean.SubjectBean;
import org.apache.wss4j.common.saml.bean.SubjectLocalityBean;
import org.apache.wss4j.common.saml.bean.Version;
import org.apache.wss4j.common.saml.builder.SAML2Constants;
import org.joda.time.DateTime;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class SAMLTokenCallbackHandler implements CallbackHandler {

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

        for (Callback cb : callbacks) {
            if (!(cb instanceof SAMLCallback)) {
                continue;
            }

            String subjectName = "uid=joe,ou=people,ou=saml-demo,o=example.com";
            String subjectQualifier = "www.example.com";
            String confirmationMethod = SAML2Constants.CONF_SENDER_VOUCHES;

            String issuer = "www.example.com";
            String issuerKeyName = "bethal";
            String issuerKeyPassword = "password";
            Crypto issuerCrypto = null;

            try {
                // pretend we are also the issuer since the server trusts us
                issuerCrypto = CryptoFactory.getInstance("etc/Client_Sign.properties", getClass().getClassLoader());
            } catch (WSSecurityException e) {
                throw new RuntimeException(e);
            }

            SAMLCallback samlCallback = (SAMLCallback) cb;
            samlCallback.setSamlVersion(Version.SAML_20);
            samlCallback.setIssuer(issuer);
            samlCallback.setIssuerFormat("urn:oasis:names:tc:SAML1.1:nameid-format:unspecified");
            samlCallback.setCanonicalizationAlgorithm(CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS);
            samlCallback.setSignAssertion(false);
            samlCallback.setIssuerCrypto(issuerCrypto);
            samlCallback.setIssuerKeyName(issuerKeyName);
            samlCallback.setIssuerKeyPassword(issuerKeyPassword);
            samlCallback.setSendKeyValue(true);

            samlCallback.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
            samlCallback.setSignatureDigestAlgorithm("http://www.w3.org/2001/04/xmlenc#sha256");

            SubjectBean subject = new SubjectBean();
            subject.setSubjectName(subjectName);
            subject.setSubjectNameIDFormat("urn:oasis:names:tc:xspa:1.0:subject:subject-id");
            subject.setSubjectConfirmationMethod(confirmationMethod);
            samlCallback.setSubject(subject);

            // authn
            AuthenticationStatementBean authStatement = new AuthenticationStatementBean();
            authStatement.setSubject(subject);
            authStatement.setAuthenticationInstant(DateTime.now());
            authStatement.setSubjectLocality(new SubjectLocalityBean("127.0.0.1", "localhost"));
            List<AuthenticationStatementBean> authStatements = new ArrayList<>();
            authStatements.add(authStatement);
            samlCallback.setAuthenticationStatementData(authStatements);

            // statements
            AttributeStatementBean stmt = new AttributeStatementBean();
            stmt.setSubject(subject);
            List<AttributeBean> attributes = new ArrayList<>();
            attributes.add(new AttributeBean(null, "urn:oasis:names:tc:xspa:1.0:subject:subject-id", Collections.singletonList(subjectQualifier)));
            stmt.setSamlAttributes(attributes);
            List<AttributeStatementBean> statements = new ArrayList<>();
            statements.add(stmt);
            samlCallback.setAttributeStatementData(statements);
        }
    }
}
