package com.bolsadeideas.springboot.app;

import com.bolsadeideas.springboot.app.handler.LoginSuccessHandler;
import com.bolsadeideas.springboot.app.models.service.JpaUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.sql.DataSource;

@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private LoginSuccessHandler successHandler;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private JpaUserDetailsService jpaUserDetailsService;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        /*Cuando tiene los astericos despues, se indica que se permite cualquier url que empiece con esa palabra*/
        http.authorizeRequests().antMatchers("/", "/css/**", "/js/**", "/images/**", "/api/listarCliente", "/listar", "/locale").permitAll()
                /*.antMatchers("/ver/**").hasAnyRole("USER")*/
                /*.antMatchers("/uploads/**").hasAnyRole("USER")*/
                /*.antMatchers("/form/**").hasAnyRole("ADMIN")*/
                /*.antMatchers("/eliminar/**").hasAnyRole("ADMIN")*/
                /*.antMatchers("/factura/**").hasAnyRole("ADMIN")*/
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .successHandler(successHandler)
                .loginPage("/login")
                .permitAll()
                .and()
                .logout().permitAll()
                .and()
                .exceptionHandling().accessDeniedPage("/error_403");
    }

    @Autowired
    public void configurerGlobal(AuthenticationManagerBuilder build) throws Exception {
        build.userDetailsService(jpaUserDetailsService)
                .passwordEncoder(bCryptPasswordEncoder);

        /*
         * Deprecated
         * UserBuilder users = User.withDefaultPasswordEncoder();


        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        User.UserBuilder users = User.builder().passwordEncoder(encoder::encode);

        build.inMemoryAuthentication()
                .withUser(users.username("ruben").password("password").roles("ADMIN", "USER"))
                .withUser(users.username("erick").password("password").roles("USER"));
        build.jdbcAuthentication()
                .dataSource(dataSource)
                .passwordEncoder(bCryptPasswordEncoder)
                .usersByUsernameQuery("SELECT username, password, enable FROM users WHERE username=?")
                .authoritiesByUsernameQuery("SELECT u.username,a.authority FROM authorities a INNER JOIN users u ON (a.user_id=u.id) WHERE u.username=?");*/

    }


}