package com.tpi.gateway;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.beans.factory.annotation.Value;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
    @Value("${KEYCLOAK_JWK_SET_URI:http://localhost:8081/realms/tpi-backend/protocol/openid-connect/certs}")
    private String jwkSetUri;

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeExchange(exchanges -> exchanges
                .pathMatchers("/actuator/**").permitAll()
                .anyExchange().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2.jwt().jwtDecoder(jwtDecoder()));
        return http.build();
    }

    // JWT Decoder que omite la validación del issuer
    @Bean
    public JwtDecoder jwtDecoder() {
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
        jwtDecoder.setJwtValidator(token -> {
            try {
                Jwt jwt = token.getJwt();
                // Solo valida la firma y expiración, ignora el issuer
                JwtValidators.createDefault().validate(jwt);
                return org.springframework.security.oauth2.jwt.OAuth2TokenValidatorResult.success();
            } catch (JwtException e) {
                return org.springframework.security.oauth2.jwt.OAuth2TokenValidatorResult.failure(
                    new org.springframework.security.oauth2.jwt.OAuth2Error("invalid_token", e.getMessage(), null)
                );
            }
        });
        return jwtDecoder;
    }
}
