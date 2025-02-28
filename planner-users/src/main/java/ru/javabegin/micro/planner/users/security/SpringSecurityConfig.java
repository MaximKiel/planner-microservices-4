package ru.javabegin.micro.planner.users.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import ru.javabegin.micro.planner.utils.converter.KCRoleConverter;

@Configuration // данный класс будет считан как конфиг для spring контейнера
@EnableWebSecurity // включает механизм защиты адресов, которые настраиваются в SecurityFilterChain
@EnableGlobalMethodSecurity(prePostEnabled = true) // включение механизма для защиты методов по ролям
public class SpringSecurityConfig {

    // создается спец. бин, который отвечает за настройки запросов по http (метод вызывается автоматически) Spring контейнером
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // конвертер для настройки spring security
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        // подключаем конвертер ролей
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KCRoleConverter());


        // все сетевые настройки
        http.authorizeRequests()
                .antMatchers("/admin/*").hasRole("admin") // CRUD для работы с пользователями
                .antMatchers("/auth/*").hasRole("user") // действия самого пользователям (регистрация и пр.)

                .anyRequest().authenticated() // остальной API будет доступен только аутентифицированным пользователям

                .and() // добавляем новые настройки, не связанные с предыдущими

                .oauth2ResourceServer()// добавляем конвертер ролей из JWT в Authority (Role)
                .jwt()
                .jwtAuthenticationConverter(jwtAuthenticationConverter);


        return http.build();
    }


}
