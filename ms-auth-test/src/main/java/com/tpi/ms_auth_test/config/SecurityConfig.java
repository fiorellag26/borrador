// para correr esta poronga localmente y que funcione: mvn spring-boot:run

package com.tpi.ms_auth_test.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth

                //acceden todos
                .requestMatchers("/public/**").permitAll()

                //accedida por roles autenticados
                .requestMatchers("/secured/**").hasAnyRole("USUARIO", "ADMIN")
                
                //accedida con admin
                .requestMatchers("/admin-only/**").hasRole("ADMIN")
                .anyRequest().denyAll()
            )
            .oauth2ResourceServer(oauth2 ->
                oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
            );

        return http.build();
    }

    // Converter para extraer roles del realm_access claim
    @Bean
    Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter() {
        return new Converter<Jwt, AbstractAuthenticationToken>() {
            @Override
            public AbstractAuthenticationToken convert(Jwt jwt) {
                Map<String, List<String>> realmAccess = jwt.getClaim("realm_access");
                
                List<String> roles = List.of();
                if (realmAccess != null && realmAccess.get("roles") != null) {
                    roles = realmAccess.get("roles");
                }

                List<GrantedAuthority> authorities = roles.stream()
                    .map(r -> "ROLE_" + r.toUpperCase())
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
                
                return new JwtAuthenticationToken(jwt, authorities);
            }
        };
    }
    
}