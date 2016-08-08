<?xml version='1.0' encoding='UTF-8'?>
<hudson>
  <disabledAdministrativeMonitors/>
  <version>1.651</version>
  <numExecutors>5</numExecutors>
  <mode>NORMAL</mode>
  <useSecurity>true</useSecurity>
  <authorizationStrategy class="hudson.security.GlobalMatrixAuthorizationStrategy">
    <permission>hudson.model.Computer.Configure:system_builder</permission>
    <permission>hudson.model.Hudson.Administer:system_builder</permission>
    <permission>hudson.model.Computer.Configure:admin</permission>
    <permission>hudson.model.Computer.Delete:admin</permission>
    <permission>hudson.model.Hudson.Administer:admin</permission>
    <permission>hudson.model.Hudson.Read:admin</permission>
    <permission>hudson.model.Hudson.Read:system_builder</permission>
    <permission>hudson.model.Item.Build:admin</permission>
    <permission>hudson.model.Item.Configure:admin</permission>
    <permission>hudson.model.Item.Create:admin</permission>
    <permission>hudson.model.Item.Delete:admin</permission>
    <permission>hudson.model.Item.Read:admin</permission>
    <permission>hudson.model.Item.Workspace:admin</permission>
    <permission>hudson.model.Run.Delete:admin</permission>
    <permission>hudson.model.Run.Update:admin</permission>
    <permission>hudson.model.View.Configure:admin</permission>
    <permission>hudson.model.View.Create:admin</permission>
    <permission>hudson.model.View.Delete:admin</permission>
    <permission>hudson.scm.SCM.Tag:admin</permission>
    <permission>hudson.model.Computer.Configure:edit</permission>
    <permission>hudson.model.Computer.Delete:edit</permission>
    <permission>hudson.model.Hudson.Administer:edit</permission>
    <permission>hudson.model.Hudson.Read:edit</permission>
    <permission>hudson.model.Hudson.Read:system_builder</permission>
    <permission>hudson.model.Item.Build:edit</permission>
    <permission>hudson.model.Item.Configure:edit</permission>
    <permission>hudson.model.Item.Create:edit</permission>
    <permission>hudson.model.Item.Delete:edit</permission>
    <permission>hudson.model.Item.Read:edit</permission>
    <permission>hudson.model.Item.Workspace:edit</permission>
    <permission>hudson.model.Run.Delete:edit</permission>
    <permission>hudson.model.Run.Update:edit</permission>
    <permission>hudson.model.View.Configure:edit</permission>
    <permission>hudson.model.View.Create:edit</permission>
    <permission>hudson.model.View.Delete:edit</permission>
    <permission>hudson.scm.SCM.Tag:edit</permission>
  </authorizationStrategy>
  <disableRememberMe>false</disableRememberMe>
  <workspaceDir>${ITEM_ROOTDIR}/workspace</workspaceDir>
  <buildsDir>${ITEM_ROOTDIR}/builds</buildsDir>
  <markupFormatter class="hudson.markup.RawHtmlMarkupFormatter"/>
  <jdks/>
  <viewsTabBar class="hudson.views.DefaultViewsTabBar"/>
  <myViewsTabBar class="hudson.views.DefaultMyViewsTabBar"/>
  <clouds>
    ${KUBERNETES_CONFIG}
  </clouds>
  <quietPeriod>1</quietPeriod>
  <scmCheckoutRetryCount>0</scmCheckoutRetryCount>
  <views>
    <hudson.model.AllView>
      <owner class="hudson" reference="../../.."/>
      <name>All</name>
      <filterExecutors>false</filterExecutors>
      <filterQueue>false</filterQueue>
      <properties/>
    </hudson.model.AllView>
  </views>
  <primaryView>All</primaryView>
  <slaveAgentPort>${JENKINS_JNLP_SERVICE_PORT}</slaveAgentPort>
  <label>master</label>
  <nodeProperties/>
  <globalNodeProperties/>
  <noUsageStatistics>true</noUsageStatistics>

  <securityRealm class="org.openshift.jenkins.plugins.openshiftlogin.OpenShiftOAuth2SecurityRealm" plugin="jenkins-openshift-login@0.1-SNAPSHOT">
    <transport class="com.google.api.client.http.javanet.NetHttpTransport">
      <connectionFactory class="com.google.api.client.http.javanet.DefaultConnectionFactory"/>
      <sslSocketFactory class="sun.security.ssl.SSLSocketFactoryImpl">
        <context class="sun.security.ssl.SSLContextImpl$TLSContext">
          <ephemeralKeyManager>
            <keys>
              <sun.security.ssl.EphemeralKeyManager_-EphemeralKeyPair>
                <uses>0</uses>
                <expirationTime>1470681151948</expirationTime>
              </sun.security.ssl.EphemeralKeyManager_-EphemeralKeyPair>
              <sun.security.ssl.EphemeralKeyManager_-EphemeralKeyPair>
                <uses>0</uses>
                <expirationTime>1470681151948</expirationTime>
              </sun.security.ssl.EphemeralKeyManager_-EphemeralKeyPair>
            </keys>
          </ephemeralKeyManager>
          <clientCache>
            <sessionCache class="sun.security.util.MemoryCache">
              <cacheMap class="linked-hash-map"/>
              <maxSize>0</maxSize>
              <lifetime>86400000</lifetime>
              <queue>
                <lock/>
                <queueLength>0</queueLength>
              </queue>
            </sessionCache>
            <sessionHostPortCache class="sun.security.util.MemoryCache">
              <cacheMap class="linked-hash-map"/>
              <maxSize>0</maxSize>
              <lifetime>86400000</lifetime>
              <queue>
                <lock/>
                <queueLength>0</queueLength>
              </queue>
            </sessionHostPortCache>
            <cacheLimit>0</cacheLimit>
            <timeout>86400</timeout>
          </clientCache>
          <serverCache>
            <sessionCache class="sun.security.util.MemoryCache">
              <cacheMap class="linked-hash-map"/>
              <maxSize>0</maxSize>
              <lifetime>86400000</lifetime>
              <queue>
                <lock/>
                <queueLength>0</queueLength>
              </queue>
            </sessionCache>
            <sessionHostPortCache class="sun.security.util.MemoryCache">
              <cacheMap class="linked-hash-map"/>
              <maxSize>0</maxSize>
              <lifetime>86400000</lifetime>
              <queue>
                <lock/>
                <queueLength>0</queueLength>
              </queue>
            </sessionHostPortCache>
            <cacheLimit>0</cacheLimit>
            <timeout>86400</timeout>
          </serverCache>
          <isInitialized>true</isInitialized>
          <keyManager class="sun.security.ssl.DummyX509KeyManager"/>
          <trustManager class="sun.security.ssl.X509TrustManagerImpl">
            <validatorType>PKIX</validatorType>
            <trustedCerts class="set">
              <sun.security.x509.X509CertImpl resolves-to="java.security.cert.Certificate$CertificateRep">
                <type>X.509</type>
                <data>CA_CRT</data>
              </sun.security.x509.X509CertImpl>
            </trustedCerts>
          </trustManager>
          <secureRandom serialization="custom">
            <java.util.Random>
              <default>
                <seed>0</seed>
                <nextNextGaussian>0.0</nextNextGaussian>
                <haveNextNextGaussian>false</haveNextNextGaussian>
              </default>
            </java.util.Random>
            <java.security.SecureRandom>
              <default>
                <counter>0</counter>
                <randomBytesUsed>0</randomBytesUsed>
                <algorithm>NativePRNG</algorithm>
                <provider class="sun.security.provider.Sun" serialization="custom">
                  <unserializable-parents/>
                  <hashtable>
                    <default>
                      <loadFactor>0.75</loadFactor>
                      <threshold>143</threshold>
                    </default>
                    <int>191</int>
                    <int>100</int>
                    <string>Alg.Alias.Signature.1.2.840.10040.4.3</string>
                    <string>SHA1withDSA</string>
                    <string>Alg.Alias.Signature.SHA1/DSA</string>
                    <string>SHA1withDSA</string>
                    <string>Alg.Alias.Signature.DSS</string>
                    <string>SHA1withDSA</string>
                    <string>SecureRandom.SHA1PRNG ImplementedIn</string>
                    <string>Software</string>
                    <string>KeyStore.JKS</string>
                    <string>sun.security.provider.JavaKeyStore$DualFormatJKS</string>
                    <string>MessageDigest.SHA</string>
                    <string>sun.security.provider.SHA</string>
                    <string>Alg.Alias.MessageDigest.SHA-1</string>
                    <string>SHA</string>
                    <string>KeyStore.CaseExactJKS</string>
                    <string>sun.security.provider.JavaKeyStore$CaseExactJKS</string>
                    <string>CertStore.com.sun.security.IndexedCollection ImplementedIn</string>
                    <string>Software</string>
                    <string>Signature.SHA256withDSA</string>
                    <string>sun.security.provider.DSA$SHA256withDSA</string>
                    <string>Alg.Alias.MessageDigest.OID.1.3.14.3.2.26</string>
                    <string>SHA</string>
                    <string>Alg.Alias.Signature.DSA</string>
                    <string>SHA1withDSA</string>
                    <string>KeyFactory.DSA ImplementedIn</string>
                    <string>Software</string>
                    <string>KeyStore.JKS ImplementedIn</string>
                    <string>Software</string>
                    <string>AlgorithmParameters.DSA ImplementedIn</string>
                    <string>Software</string>
                    <string>Signature.NONEwithDSA</string>
                    <string>sun.security.provider.DSA$RawDSA</string>
                    <string>Alg.Alias.CertificateFactory.X509</string>
                    <string>X.509</string>
                    <string>Signature.SHA256withDSA SupportedKeyClasses</string>
                    <string>java.security.interfaces.DSAPublicKey|java.security.interfaces.DSAPrivateKey</string>
                    <string>CertStore.com.sun.security.IndexedCollection</string>
                    <string>sun.security.provider.certpath.IndexedCollectionCertStore</string>
                    <string>Provider.id className</string>
                    <string>sun.security.provider.Sun</string>
                    <string>Alg.Alias.MessageDigest.1.3.14.3.2.26</string>
                    <string>SHA</string>
                    <string>Alg.Alias.Signature.SHA-1/DSA</string>
                    <string>SHA1withDSA</string>
                    <string>KeyStore.DKS</string>
                    <string>sun.security.provider.DomainKeyStore$DKS</string>
                    <string>Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.2</string>
                    <string>SHA256withDSA</string>
                    <string>CertificateFactory.X.509 ImplementedIn</string>
                    <string>Software</string>
                    <string>Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.1</string>
                    <string>SHA224withDSA</string>
                    <string>Signature.SHA1withDSA KeySize</string>
                    <string>1024</string>
                    <string>Signature.NONEwithDSA KeySize</string>
                    <string>1024</string>
                    <string>KeyFactory.DSA</string>
                    <string>sun.security.provider.DSAKeyFactory</string>
                    <string>CertPathValidator.PKIX ImplementedIn</string>
                    <string>Software</string>
                    <string>Alg.Alias.Signature.OID.1.2.840.10040.4.3</string>
                    <string>SHA1withDSA</string>
                    <string>Configuration.JavaLoginConfig</string>
                    <string>sun.security.provider.ConfigFile$Spi</string>
                    <string>Alg.Alias.KeyFactory.1.2.840.10040.4.1</string>
                    <string>DSA</string>
                    <string>Alg.Alias.MessageDigest.OID.2.16.840.1.101.3.4.2.4</string>
                    <string>SHA-224</string>
                    <string>Alg.Alias.MessageDigest.OID.2.16.840.1.101.3.4.2.3</string>
                    <string>SHA-512</string>
                    <string>MessageDigest.MD5 ImplementedIn</string>
                    <string>Software</string>
                    <string>Alg.Alias.MessageDigest.OID.2.16.840.1.101.3.4.2.2</string>
                    <string>SHA-384</string>
                    <string>Alg.Alias.MessageDigest.OID.2.16.840.1.101.3.4.2.1</string>
                    <string>SHA-256</string>
                    <string>Provider.id name</string>
                    <string>SUN</string>
                    <string>Alg.Alias.Signature.RawDSA</string>
                    <string>NONEwithDSA</string>
                    <string>Alg.Alias.AlgorithmParameters.1.2.840.10040.4.1</string>
                    <string>DSA</string>
                    <string>CertPathBuilder.PKIX ValidationAlgorithm</string>
                    <string>RFC3280</string>
                    <string>Policy.JavaPolicy</string>
                    <string>sun.security.provider.PolicySpiFile</string>
                    <string>Alg.Alias.AlgorithmParameters.OID.1.2.840.10040.4.1</string>
                    <string>DSA</string>
                    <string>Signature.SHA224withDSA KeySize</string>
                    <string>2048</string>
                    <string>MessageDigest.SHA-384</string>
                    <string>sun.security.provider.SHA5$SHA384</string>
                    <string>Alg.Alias.KeyPairGenerator.1.3.14.3.2.12</string>
                    <string>DSA</string>
                    <string>Alg.Alias.Signature.SHA/DSA</string>
                    <string>SHA1withDSA</string>
                    <string>Alg.Alias.AlgorithmParameters.1.3.14.3.2.12</string>
                    <string>DSA</string>
                    <string>MessageDigest.SHA-224</string>
                    <string>sun.security.provider.SHA2$SHA224</string>
                    <string>Signature.SHA1withDSA ImplementedIn</string>
                    <string>Software</string>
                    <string>AlgorithmParameterGenerator.DSA</string>
                    <string>sun.security.provider.DSAParameterGenerator</string>
                    <string>Signature.NONEwithDSA SupportedKeyClasses</string>
                    <string>java.security.interfaces.DSAPublicKey|java.security.interfaces.DSAPrivateKey</string>
                    <string>SecureRandom.NativePRNGBlocking</string>
                    <string>sun.security.provider.NativePRNG$Blocking</string>
                    <string>MessageDigest.SHA-512</string>
                    <string>sun.security.provider.SHA5$SHA512</string>
                    <string>Alg.Alias.KeyFactory.OID.1.2.840.10040.4.1</string>
                    <string>DSA</string>
                    <string>CertPathBuilder.PKIX</string>
                    <string>sun.security.provider.certpath.SunCertPathBuilder</string>
                    <string>Alg.Alias.Signature.1.3.14.3.2.27</string>
                    <string>SHA1withDSA</string>
                    <string>Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.4</string>
                    <string>SHA-224</string>
                    <string>Provider.id version</string>
                    <string>1.8</string>
                    <string>Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.3</string>
                    <string>SHA-512</string>
                    <string>CertPathBuilder.PKIX ImplementedIn</string>
                    <string>Software</string>
                    <string>Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.2</string>
                    <string>SHA-384</string>
                    <string>Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.1</string>
                    <string>SHA-256</string>
                    <string>Signature.SHA256withDSA KeySize</string>
                    <string>2048</string>
                    <string>AlgorithmParameters.DSA</string>
                    <string>sun.security.provider.DSAParameters</string>
                    <string>Signature.SHA1withDSA SupportedKeyClasses</string>
                    <string>java.security.interfaces.DSAPublicKey|java.security.interfaces.DSAPrivateKey</string>
                    <string>CertStore.Collection</string>
                    <string>sun.security.provider.certpath.CollectionCertStore</string>
                    <string>AlgorithmParameterGenerator.DSA ImplementedIn</string>
                    <string>Software</string>
                    <string>SecureRandom.NativePRNGNonBlocking</string>
                    <string>sun.security.provider.NativePRNG$NonBlocking</string>
                    <string>KeyPairGenerator.DSA KeySize</string>
                    <string>2048</string>
                    <string>CertStore.LDAP</string>
                    <string>sun.security.provider.certpath.ldap.LDAPCertStore</string>
                    <string>Alg.Alias.Signature.2.16.840.1.101.3.4.3.2</string>
                    <string>SHA256withDSA</string>
                    <string>CertificateFactory.X.509</string>
                    <string>sun.security.provider.X509Factory</string>
                    <string>Alg.Alias.Signature.2.16.840.1.101.3.4.3.1</string>
                    <string>SHA224withDSA</string>
                    <string>SecureRandom.NativePRNG</string>
                    <string>sun.security.provider.NativePRNG</string>
                    <string>CertStore.LDAP LDAPSchema</string>
                    <string>RFC2587</string>
                    <string>KeyPairGenerator.DSA ImplementedIn</string>
                    <string>Software</string>
                    <string>CertStore.LDAP ImplementedIn</string>
                    <string>Software</string>
                    <string>CertPathValidator.PKIX ValidationAlgorithm</string>
                    <string>RFC3280</string>
                    <string>Signature.SHA224withDSA</string>
                    <string>sun.security.provider.DSA$SHA224withDSA</string>
                    <string>CertStore.Collection ImplementedIn</string>
                    <string>Software</string>
                    <string>Alg.Alias.Signature.1.3.14.3.2.13</string>
                    <string>SHA1withDSA</string>
                    <string>CertPathValidator.PKIX</string>
                    <string>sun.security.provider.certpath.PKIXCertPathValidator</string>
                    <string>Alg.Alias.MessageDigest.SHA1</string>
                    <string>SHA</string>
                    <string>AlgorithmParameterGenerator.DSA KeySize</string>
                    <string>2048</string>
                    <string>SecureRandom.SHA1PRNG</string>
                    <string>sun.security.provider.SecureRandom</string>
                    <string>Signature.SHA1withDSA</string>
                    <string>sun.security.provider.DSA$SHA1withDSA</string>
                    <string>Alg.Alias.KeyFactory.1.3.14.3.2.12</string>
                    <string>DSA</string>
                    <string>KeyPairGenerator.DSA</string>
                    <string>sun.security.provider.DSAKeyPairGenerator</string>
                    <string>MessageDigest.SHA ImplementedIn</string>
                    <string>Software</string>
                    <string>Provider.id info</string>
                    <string>SUN (DSA key/parameter generation; DSA signing; SHA-1, MD5 digests; SecureRandom; X.509 certificates; JKS &amp; DKS keystores; PKIX CertPathValidator; PKIX CertPathBuilder; LDAP, Collection CertStores, JavaPolicy Policy; JavaLoginConfig Configuration)</string>
                    <string>Alg.Alias.KeyPairGenerator.1.2.840.10040.4.1</string>
                    <string>DSA</string>
                    <string>MessageDigest.SHA-256</string>
                    <string>sun.security.provider.SHA2$SHA256</string>
                    <string>Alg.Alias.Signature.DSAWithSHA1</string>
                    <string>SHA1withDSA</string>
                    <string>MessageDigest.MD5</string>
                    <string>sun.security.provider.MD5</string>
                    <string>Alg.Alias.Signature.SHAwithDSA</string>
                    <string>SHA1withDSA</string>
                    <string>Alg.Alias.KeyPairGenerator.OID.1.2.840.10040.4.1</string>
                    <string>DSA</string>
                    <string>Signature.SHA224withDSA SupportedKeyClasses</string>
                    <string>java.security.interfaces.DSAPublicKey|java.security.interfaces.DSAPrivateKey</string>
                    <string>MessageDigest.MD2</string>
                    <string>sun.security.provider.MD2</string>
                  </hashtable>
                  <java.security.Provider>
                    <default>
                      <version>1.8</version>
                      <info>SUN (DSA key/parameter generation; DSA signing; SHA-1, MD5 digests; SecureRandom; X.509 certificates; JKS &amp; DKS keystores; PKIX CertPathValidator; PKIX CertPathBuilder; LDAP, Collection CertStores, JavaPolicy Policy; JavaLoginConfig Configuration)</info>
                      <name>SUN</name>
                    </default>
                  </java.security.Provider>
                </provider>
                <secureRandomSpi class="sun.security.provider.NativePRNG"/>
              </default>
            </java.security.SecureRandom>
          </secureRandom>
        </context>
      </sslSocketFactory>
    </transport>
    <serviceAccountDirectory>/var/run/secrets/kubernetes.io/serviceaccount</serviceAccountDirectory>
    <serviceAccountName>SA_SHORT_NAME</serviceAccountName>
    <serverPrefix>MASTER_PREFIX</serverPrefix>
    <clientId>SA_NAME</clientId>
    <clientSecret>SA_TOKEN</clientSecret>
  </securityRealm>

</hudson>
