// para correr esta poronga localmente y que funcione: mvn spring-boot:run

package com.tpi.ms_auth_test.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
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
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .requestMatchers("/secured/**").authenticated()  // ✅ Solo token válido
                .requestMatchers("/admin-only/**").hasRole("admin")  // ✅ Requiere ROLE_admin
                .anyRequest().denyAll()
            )
            .oauth2ResourceServer(oauth2 ->
                oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
            );

        return http.build();
    }

    // -----------------------------
    // CONVERTER EXACTO DEL APUNTE
    // -----------------------------
    @Bean
    public Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter() {
        return new Converter<Jwt, AbstractAuthenticationToken>() {
            @Override
            public AbstractAuthenticationToken convert(Jwt jwt) {
                
                // 🔍 LOG 1: Ver todos los claims del token
                System.out.println("📋 TODOS LOS CLAIMS:");
                jwt.getClaims().forEach((key, value) -> 
                    System.out.println("  " + key + " = " + value)
                );
                
                // Obtiene el objeto realm_access
                Map<String, List<String>> realmAccess = jwt.getClaim("realm_access");
                
                // 🔍 LOG 2: Ver qué hay en realm_access
                System.out.println("🔑 realm_access = " + realmAccess);
                
                if (realmAccess == null || realmAccess.get("roles") == null) {
                    System.out.println("⚠️ NO SE ENCONTRARON ROLES EN realm_access");
                    return new JwtAuthenticationToken(jwt, List.of());
                }
                
                // 🔍 LOG 3: Ver los roles encontrados
                List<String> roles = realmAccess.get("roles");
                System.out.println("📜 ROLES encontrados: " + roles);
                
                // Convierte "cliente" → "ROLE_cliente"
                List<GrantedAuthority> authorities = roles.stream()
                        .map(r -> "ROLE_" + r)
                        .peek(role -> System.out.println("✅ Autoridad agregada: " + role))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());
                
                // 🔍 LOG 4: Ver las autoridades finales
                System.out.println("🎯 AUTORIDADES FINALES: " + authorities);
                
                return new JwtAuthenticationToken(jwt, authorities);
            }
        };
    }
}