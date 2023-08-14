package usi.si.seart.seart.admin.config;

import de.codecentric.boot.admin.server.web.client.HttpHeadersProvider;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(Customizer.withDefaults())
                .authorizeHttpRequests(
                        registry -> registry.requestMatchers(
                                "/assets/**",
                                "/login",
                                "/logout"
                        )
                        .permitAll()
                        .anyRequest()
                        .authenticated()
                )
                .formLogin(configurer -> configurer.loginPage("/login"))
                .logout(configurer -> configurer.logoutUrl("/logout").permitAll())
                .build();
    }

    @Bean
    public HttpHeadersProvider httpHeadersProvider() {
        return instance -> {
            HttpHeaders httpHeaders = new HttpHeaders();
            // FIXME: 16.06.23 Currently only works for GHS
            Map<String, String> credentials = credentialsConfig().getCredentials();
            httpHeaders.add(HttpHeaders.AUTHORIZATION, credentials.get("ghs"));
            return httpHeaders;
        };
    }

    @Bean
    public CredentialsConfig credentialsConfig() {
        return new CredentialsConfig();
    }

    @ConfigurationProperties("admin")
    public static final class CredentialsConfig {

        private final Map<String, String> credentials = new HashMap<>();

        private CredentialsConfig() {
        }

        public Map<String, String> getCredentials() {
            return credentials;
        }
    }
}
