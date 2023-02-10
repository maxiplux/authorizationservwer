package com.example.authorizationservwer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import javax.sql.DataSource;
import java.net.MalformedURLException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

@Configuration
@EnableAuthorizationServer
public class SecurityOAuth2Configuration extends AuthorizationServerConfigurerAdapter {
    private String privateKey = "sdfsdfn" ;


    private String publicKey = "miibijanbgkqhkig9w0baqefaaocaq8amiibcgkcaqeautlov3xrz36knmc0smeynvkc5aha93hhcu7dlxrg8garxyzirtcivyd6tqz4yxr+m8bko7cl0v///2wvwx5i58bioqfmmql/yykoib92ssxo2lypcqhzazjqyktwhfjj5x/vcktd90pnaozqvgo8o9c4bgo2jgrdt9g/halxjotzcya4wb93vacpidhwr+g4gxfw3fvi93jhhotg9leus9uivmxwjwaff6leummuutxhoqhlsamildclchjayfzaupahrtvdelx53nsmu5pk3n19wiepqww7gvb1tgdakibhuyply6jlntiblbyhc5nj4fpuntpnporgdexj5yjp9qidaqab";

    @Value("classpath:authserver.jks")
    Resource resourceFile;



    @Autowired
    private AuthenticationManager authenticationManager;
    @Bean
    public JwtAccessTokenConverter tokenEnhancer() throws NoSuchAlgorithmException {
        //https://www.baeldung.com/spring-security-oauth-jwt-legacy
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();

        //KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory( resourceFile , "passwordhere".toCharArray());

        //converter.setSigningKey("123");
        //converter.setVerifierKey(String.format("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", publicKey));

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);

        KeyPair pair = generator.generateKeyPair();



        converter.setKeyPair(pair);
        return converter;
    }



    @Bean
    public TokenStore tokenStore() {
        return new InMemoryTokenStore();
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("javadeveloperzone")
                .secret("secret")
                .accessTokenValiditySeconds(3600)        // expire time for access token
                .refreshTokenValiditySeconds(-1)         // expire time for refresh token
                .scopes("read", "write")                         // scope related to resource server
                .authorizedGrantTypes("password", "refresh_token");      // grant type

    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager).accessTokenConverter(tokenEnhancer());;


        //endpoints.tokenStore(tokenStore());
    }
}
