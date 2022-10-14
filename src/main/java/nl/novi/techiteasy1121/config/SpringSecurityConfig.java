package nl.novi.techiteasy1121.config;


import nl.novi.techiteasy1121.filter.JwtRequestFilter;
import nl.novi.techiteasy1121.services.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomUserDetailsService customUserDetailsService;
    private final JwtRequestFilter jwtRequestFilter;

    @Autowired
    public SpringSecurityConfig(CustomUserDetailsService customUserDetailsService, JwtRequestFilter jwtRequestFilter) {
        this.customUserDetailsService = customUserDetailsService;
        this.jwtRequestFilter = jwtRequestFilter;
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(customUserDetailsService);
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //JWT token authentication
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers(HttpMethod.POST, "/users").permitAll()
                .antMatchers(HttpMethod.GET,"/users").hasRole("ADMIN")
                .antMatchers(HttpMethod.POST,"/users/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.DELETE, "/users/**").hasRole("ADMIN")

                .antMatchers(HttpMethod.POST, "/cimodules").hasRole("ADMIN")
                .antMatchers(HttpMethod.DELETE, "/cimodules/**").hasRole("ADMIN")

                .antMatchers(HttpMethod.POST, "/remotecontrollers").hasRole("ADMIN")
                .antMatchers(HttpMethod.DELETE, "/remotecontrollers/**").hasRole("ADMIN")

                .antMatchers(HttpMethod.POST, "/televisions").hasRole("ADMIN")
                .antMatchers(HttpMethod.DELETE, "/televisions/**").hasRole("ADMIN")

                .antMatchers(HttpMethod.POST, "/wallbrackets").hasRole("ADMIN")
                .antMatchers(HttpMethod.DELETE, "/wallbrackets/**").hasRole("ADMIN")

                .antMatchers("/cimodules/**", "/remotecontrollers/**", "/televisons/**", "/wallbrackets/**").hasAnyRole("ADMIN", "USER")

                /*voeg de antmatchers toe voor admin(post en delete) en user (overige)*/
                .antMatchers("/authenticated").authenticated()
                .antMatchers("/authenticate").permitAll()/*allen dit punt mag toegankelijk zijn voor niet ingelogde gebruikers*/
                .anyRequest().permitAll()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

    }

}