package com.example.SAMLwOkta.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@Configuration
public class Saml2RelyingPartyConfiguration {

   @Bean
   @ConditionalOnMissingBean
   public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
       try {
           PrivateKey privateKey = loadPrivateKey("classpath:sp-private-key.pem");
           X509Certificate certificate = loadCertificate("classpath:sp-certificate.pem");

           Saml2X509Credential signingCredential = Saml2X509Credential.signing(
                   privateKey,
                   certificate
           );

           RelyingPartyRegistration registration = RelyingPartyRegistrations
                   .fromMetadataLocation("https://integrator-1581101.okta.com/app/exkvgzurh6B0rVra1697/sso/saml/metadata")
                   .registrationId("okta")
                   .entityId("aiv-saml-sp")
                   .signingX509Credentials(c -> c.add(signingCredential))
                   .assertionConsumerServiceBinding(Saml2MessageBinding.POST)
                   .build();

           return new InMemoryRelyingPartyRegistrationRepository(registration);
       } catch (Exception e) {
           throw new RuntimeException("Failed to create RelyingPartyRegistrationRepository", e);
       }
   }

   private PrivateKey loadPrivateKey(String resourcePath) throws Exception {
       try (InputStream inputStream = new ClassPathResource(resourcePath).getInputStream()) {
           String keyContent = new String(inputStream.readAllBytes());
           keyContent = keyContent.replace("-----BEGIN PRIVATE KEY-----", "")
                   .replace("-----END PRIVATE KEY-----", "")
                   .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                   .replace("-----END RSA PRIVATE KEY-----", "")
                   .replaceAll("\\s", "");

           byte[] keyBytes = Base64.getDecoder().decode(keyContent);
           PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
           KeyFactory keyFactory = KeyFactory.getInstance("RSA");
           return keyFactory.generatePrivate(keySpec);
       }
   }

   private X509Certificate loadCertificate(String resourcePath) throws Exception {
       try (InputStream inputStream = new ClassPathResource(resourcePath).getInputStream()) {
           CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
           return (X509Certificate) certificateFactory.generateCertificate(inputStream);
       }
   }

   private static class InMemoryRelyingPartyRegistrationRepository implements RelyingPartyRegistrationRepository {
       private final RelyingPartyRegistration registration;

       public InMemoryRelyingPartyRegistrationRepository(RelyingPartyRegistration registration) {
           this.registration = registration;
       }

       @Override
       public RelyingPartyRegistration findByRegistrationId(String registrationId) {
           if ("okta".equals(registrationId)) {
               return registration;
           }
           return null;
       }
   }
}
